use std::{env, fs, path::PathBuf};
fn main() {
    println!("cargo:rerun-if-env-changed=DEFENDER_DIAG_ANALYZER_ZIP");
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo OUT_DIR")).join("analyzer.zip");
    if let Some(path) = env::var_os("DEFENDER_DIAG_ANALYZER_ZIP") {
        let path = PathBuf::from(path);
        println!("cargo:rerun-if-changed={}", path.display());
        fs::copy(&path, &out).expect("copy supplied analyzer ZIP");
    } else {
        fs::write(out, []).expect("write empty optional analyzer bundle");
    }
}
