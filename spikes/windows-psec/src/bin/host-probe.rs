//! Task 1.1: report what the MXC SDK detects on this host.
fn main() {
    let facts = mxc_sdk::v1::platform_support();
    println!("platform_support: {facts:#?}");
    for b in mxc_sdk::v1::available_backends() {
        println!("backend: {b:?}");
    }
    match mxc_sdk::v1::probe(None) {
        Ok(out) => println!(
            "probe:\n{}",
            serde_json::to_string_pretty(&out).unwrap_or_else(|e| format!("<serialize: {e}>"))
        ),
        Err(e) => println!("probe error: {e:?}"),
    }
}
