//! Holding policy paths in place for the duration of a launch.
//!
//! PSEC resolves each policy path when the environment is created: a grant
//! that names a junction applies to the junction's target (spike §1.2). A
//! path that changed after its capability was built would therefore carry
//! the grant to another object, and a single-file grant replaced by a
//! directory would become recursive.
//!
//! Before the environment is created, every grant, deny and enumerate path
//! is opened and checked against the policy: same final path, and for
//! grants the same file or directory kind. The handles are held without
//! `FILE_SHARE_DELETE`, so the objects cannot be renamed, deleted or
//! replaced meanwhile. Once the process exists, still suspended, each path is
//! resolved again and must still name the same file.

use std::os::windows::io::{AsRawHandle, OwnedHandle};
use std::path::PathBuf;
use std::ptr::null;

use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_ATTRIBUTE_DIRECTORY, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_ID_INFO, FILE_NAME_NORMALIZED, FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, FileIdInfo, GetFileInformationByHandle,
    GetFileInformationByHandleEx, GetFinalPathNameByHandleW, OPEN_EXISTING, VOLUME_NAME_DOS,
};

use crate::capability::CapabilitySet;
use crate::error::{NonoError, Result};

use super::policy::{PathUse, WindowsPolicy, policy_path};

/// Identity of a file: volume serial number and 128-bit file ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileId {
    volume: u64,
    file: [u8; 16],
}

#[derive(Debug)]
struct Pin {
    /// The path as it appears in the policy (`X:\...`).
    path: String,
    id: FileId,
    _handle: OwnedHandle,
}

/// Open handles on every policy path. Dropping it releases them.
#[derive(Debug)]
pub(crate) struct Pins(Vec<Pin>);

impl Pins {
    /// Open and check every path the policy names. `caps` supplies the
    /// file/directory kind of each grant.
    pub(crate) fn acquire(caps: &CapabilitySet, policy: &WindowsPolicy) -> Result<Self> {
        let mut pins = Vec::new();
        for cap in caps.fs_capabilities() {
            let path = policy_path(&cap.resolved, PathUse::Grant)?;
            pins.push(pin(&path, PathUse::Grant, Some(cap.is_file))?);
        }
        for path in &policy.deny {
            pins.push(pin(path, PathUse::Deny, None)?);
        }
        for path in &policy.enumerate {
            pins.push(pin(path, PathUse::Enumerate, None)?);
        }
        Ok(Self(pins))
    }

    /// Resolve every path again; each must still name the pinned file.
    pub(crate) fn verify(&self) -> Result<()> {
        for pin in &self.0 {
            let handle = open(&pin.path, FILE_READ_ATTRIBUTES, all_sharing())?;
            if file_id(&handle, &pin.path)? != pin.id {
                return Err(changed(&pin.path));
            }
        }
        Ok(())
    }
}

fn all_sharing() -> u32 {
    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
}

fn pin(path: &str, usage: PathUse, is_file: Option<bool>) -> Result<Pin> {
    // Read-data access takes part in sharing checks, so withholding
    // FILE_SHARE_DELETE makes rename and delete fail while the handle lives.
    let handle = open(
        path,
        FILE_READ_DATA | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
    )?;
    let resolved = final_path(&handle, path)?;
    if !policy_path(&resolved, usage)?.eq_ignore_ascii_case(path) {
        return Err(changed(path));
    }
    if let Some(is_file) = is_file {
        let is_directory = attributes(&handle, path)? & FILE_ATTRIBUTE_DIRECTORY != 0;
        if is_file && is_directory {
            return Err(NonoError::ExpectedFile(PathBuf::from(path)));
        }
        if !is_file && !is_directory {
            return Err(NonoError::ExpectedDirectory(PathBuf::from(path)));
        }
    }
    Ok(Pin {
        path: path.to_string(),
        id: file_id(&handle, path)?,
        _handle: handle,
    })
}

fn changed(path: &str) -> NonoError {
    NonoError::SandboxInit(format!(
        "{path} changed after its capability was created (it now resolves to a different object); refusing to launch"
    ))
}

fn io_error(what: &str, path: &str) -> NonoError {
    NonoError::SandboxInit(format!(
        "{what} {path} failed: Win32 error {}",
        super::last_error()
    ))
}

fn open(path: &str, access: u32, sharing: u32) -> Result<OwnedHandle> {
    let wide = super::wide(path);
    // SAFETY: NUL-terminated path; null security attributes and template.
    // FILE_FLAG_BACKUP_SEMANTICS lets directories be opened; reparse points
    // are followed so the handle names the object PSEC will resolve.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            access,
            sharing,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            std::ptr::null_mut(),
        )
    };
    super::launch::owned(handle, "CreateFileW").map_err(|_| io_error("opening", path))
}

fn final_path(handle: &OwnedHandle, path: &str) -> Result<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    let mut buf = vec![0u16; 512];
    loop {
        let capacity = u32::try_from(buf.len()).unwrap_or(u32::MAX);
        // SAFETY: live handle; the buffer holds `capacity` UTF-16 units.
        let len = unsafe {
            GetFinalPathNameByHandleW(
                handle.as_raw_handle(),
                buf.as_mut_ptr(),
                capacity,
                FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
            )
        };
        let len = usize::try_from(len).unwrap_or(usize::MAX);
        if len == 0 {
            return Err(io_error("resolving", path));
        }
        if len < buf.len() {
            buf.truncate(len);
            return Ok(PathBuf::from(std::ffi::OsString::from_wide(&buf)));
        }
        // Too small: `len` is the required size including the terminator.
        buf.resize(len, 0);
    }
}

fn attributes(handle: &OwnedHandle, path: &str) -> Result<u32> {
    // SAFETY: plain data; all-zero is a valid value.
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: live handle and out-pointer.
    if unsafe { GetFileInformationByHandle(handle.as_raw_handle(), &mut info) } == 0 {
        return Err(io_error("querying", path));
    }
    Ok(info.dwFileAttributes)
}

fn file_id(handle: &OwnedHandle, path: &str) -> Result<FileId> {
    // SAFETY: plain data; all-zero is a valid value.
    let mut info: FILE_ID_INFO = unsafe { std::mem::zeroed() };
    // SAFETY: live handle; the pointer and size describe `info`.
    if unsafe {
        GetFileInformationByHandleEx(
            handle.as_raw_handle(),
            FileIdInfo,
            (&raw mut info).cast(),
            u32::try_from(std::mem::size_of::<FILE_ID_INFO>()).unwrap_or(u32::MAX),
        )
    } == 0
    {
        return Err(io_error("querying the file ID of", path));
    }
    Ok(FileId {
        volume: info.VolumeSerialNumber,
        file: info.FileId.Identifier,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AccessMode;

    fn policy_for(caps: &CapabilitySet) -> Result<WindowsPolicy> {
        let opts = super::super::LaunchOptions::new(r"C:\Windows\System32\whoami.exe", r"C:\");
        WindowsPolicy::from_launch(caps, &opts, None)
    }

    #[test]
    fn file_grant_replaced_by_a_directory_is_refused() -> Result<()> {
        let dir = tempfile::tempdir().map_err(NonoError::Io)?;
        let file = dir.path().join("grant.txt");
        std::fs::write(&file, b"x").map_err(NonoError::Io)?;
        let caps = CapabilitySet::new().allow_file(&file, AccessMode::ReadWrite)?;
        let policy = policy_for(&caps)?;
        std::fs::remove_file(&file).map_err(NonoError::Io)?;
        std::fs::create_dir(&file).map_err(NonoError::Io)?;
        assert!(file.is_dir());
        let err = Pins::acquire(&caps, &policy).err();
        assert!(matches!(err, Some(NonoError::ExpectedFile(_))), "{err:?}");
        Ok(())
    }

    #[test]
    fn directory_grant_replaced_by_a_file_is_refused() -> Result<()> {
        let dir = tempfile::tempdir().map_err(NonoError::Io)?;
        let sub = dir.path().join("sub");
        std::fs::create_dir(&sub).map_err(NonoError::Io)?;
        let caps = CapabilitySet::new().allow_path(&sub, AccessMode::Read)?;
        let policy = policy_for(&caps)?;
        std::fs::remove_dir(&sub).map_err(NonoError::Io)?;
        std::fs::write(&sub, b"x").map_err(NonoError::Io)?;
        let err = Pins::acquire(&caps, &policy).err();
        assert!(
            matches!(err, Some(NonoError::ExpectedDirectory(_))),
            "{err:?}"
        );
        Ok(())
    }

    #[test]
    fn grant_replaced_by_a_junction_is_refused() -> Result<()> {
        let dir = tempfile::tempdir().map_err(NonoError::Io)?;
        let granted = dir.path().join("granted");
        let elsewhere = dir.path().join("elsewhere");
        std::fs::create_dir(&granted).map_err(NonoError::Io)?;
        std::fs::create_dir(&elsewhere).map_err(NonoError::Io)?;
        let caps = CapabilitySet::new().allow_path(&granted, AccessMode::Read)?;
        let policy = policy_for(&caps)?;
        std::fs::remove_dir(&granted).map_err(NonoError::Io)?;
        let made = std::process::Command::new("cmd")
            .args(["/d", "/c", "mklink", "/J"])
            .arg(&granted)
            .arg(&elsewhere)
            .output()
            .map_err(NonoError::Io)?;
        assert!(made.status.success(), "mklink /J failed: {made:?}");
        let err = Pins::acquire(&caps, &policy).err();
        assert!(
            err.as_ref()
                .is_some_and(|e| e.to_string().contains("changed after its capability")),
            "{err:?}"
        );
        Ok(())
    }

    #[test]
    fn pinned_grant_cannot_be_renamed_and_verifies() -> Result<()> {
        let dir = tempfile::tempdir().map_err(NonoError::Io)?;
        let sub = dir.path().join("sub");
        std::fs::create_dir(&sub).map_err(NonoError::Io)?;
        let caps = CapabilitySet::new().allow_path(&sub, AccessMode::Read)?;
        let policy = policy_for(&caps)?;
        let pins = Pins::acquire(&caps, &policy)?;
        assert!(
            std::fs::rename(&sub, dir.path().join("moved")).is_err(),
            "a pinned directory was renamed"
        );
        pins.verify()?;
        drop(pins);
        std::fs::rename(&sub, dir.path().join("moved")).map_err(NonoError::Io)?;
        Ok(())
    }
}
