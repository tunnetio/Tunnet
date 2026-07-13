pub fn collect_system_metadata(hostname: &str, agent_version: &str) -> serde_json::Value {
    let cpu_count = std::thread::available_parallelism()
        .map(|n| n.get() as u64)
        .unwrap_or(0);

    let mut meta = serde_json::Map::new();
    meta.insert("hostname".into(), hostname.into());
    meta.insert("os".into(), std::env::consts::OS.into());
    meta.insert("arch".into(), std::env::consts::ARCH.into());
    meta.insert("family".into(), std::env::consts::FAMILY.into());
    meta.insert("agentVersion".into(), agent_version.into());
    meta.insert("cpuCount".into(), cpu_count.into());
    meta.insert("reportedAt".into(), chrono::Utc::now().to_rfc3339().into());

    if let Some(os_version) = read_os_version() {
        meta.insert("osVersion".into(), os_version.into());
    }
    if let Some(total_memory_bytes) = read_total_memory_bytes() {
        meta.insert("totalMemoryBytes".into(), total_memory_bytes.into());
    }

    serde_json::Value::Object(meta)
}

fn read_os_version() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        let content = std::fs::read_to_string("/etc/os-release").ok()?;
        for line in content.lines() {
            if let Some(rest) = line.strip_prefix("PRETTY_NAME=") {
                return Some(rest.trim_matches('"').to_string());
            }
        }
        None
    }

    #[cfg(target_os = "macos")]
    {
        let output = std::process::Command::new("sw_vers")
            .arg("-productVersion")
            .output()
            .ok()?;
        let version = String::from_utf8(output.stdout).ok()?;
        let version = version.trim();
        if version.is_empty() {
            return None;
        }
        return Some(format!("macOS {version}"));
    }

    #[cfg(target_os = "windows")]
    {
        let output = std::process::Command::new("cmd")
            .args(["/C", "ver"])
            .output()
            .ok()?;
        let version = String::from_utf8(output.stdout).ok()?;
        let version = version.trim();
        if version.is_empty() {
            return None;
        }
        Some(version.to_string())
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        None
    }
}

fn read_total_memory_bytes() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let content = std::fs::read_to_string("/proc/meminfo").ok()?;
        for line in content.lines() {
            if let Some(kb) = line.strip_prefix("MemTotal:") {
                let kb = kb.trim().trim_end_matches(" kB").parse::<u64>().ok()?;
                return Some(kb * 1024);
            }
        }
        None
    }

    #[cfg(target_os = "macos")]
    {
        let output = std::process::Command::new("sysctl")
            .args(["-n", "hw.memsize"])
            .output()
            .ok()?;
        let bytes = String::from_utf8(output.stdout).ok()?;
        return bytes.trim().parse::<u64>().ok();
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        None
    }
}
