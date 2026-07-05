use std::path::PathBuf;

pub fn resolve(explicit: Option<&str>) -> PathBuf {
    if let Some(path) = explicit {
        return PathBuf::from(path);
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let beside = dir.join("wintun.dll");
            if beside.is_file() {
                return beside;
            }
        }
    }
    PathBuf::from("wintun.dll")
}
