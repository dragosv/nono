# Vendored PSEC FlatBuffer bindings

`mod.rs` and `process_security_environment_layout/` are copied unmodified
from `mxc-sdk` 1.0.1 (`src/core/process_security_environment_spec/`):
- crates.io `.crate` sha256 `7c9e2d05b3953fdb34c44e4de8d8f2b447f4444534cb95294b72fb297a468f61`
- microsoft/mxc tag `v1.0.1` = `fda29ac63bc306b7f97f3b86b4b63d44f7f40cf2`

They were generated with flatc 25.12.19 from
`external/windows-sdk/ProcessSecurityEnvironment.fbs`. Per the MXC
provenance file, that schema originates in the Windows OS repository and was
validated against build 10.0.26690.0, schema sha256
`736cacef37a6c97a0cb97c7132da462a3b51811fca8f1e4076cac51085dfa516`. It is
not part of the public Windows SDK 10.0.26100.

License: MIT, see `LICENSE-MIT`. Copyright (c) Microsoft Corporation.

Do not edit these files by hand. To update, regenerate with the pinned flatc
from the pinned schema, record the new hashes here, and keep the
`flatbuffers` crate pinned to the same release.
