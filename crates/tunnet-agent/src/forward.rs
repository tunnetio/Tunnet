#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use anyhow::Context;
use anyhow::{Result, bail};
use ipnet::Ipv4Net;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use std::process::Command;

pub struct GatewayGuard {
    #[cfg(target_os = "linux")]
    forwarding: Vec<(std::path::PathBuf, String)>,
    #[cfg(target_os = "linux")]
    table: Option<String>,
    #[cfg(target_os = "windows")]
    forwarding: Vec<(String, String)>,
    #[cfg(target_os = "windows")]
    nat: Option<String>,
    #[cfg(target_os = "macos")]
    forwarding: Option<String>,
    #[cfg(target_os = "macos")]
    anchor: Option<String>,
    #[cfg(target_os = "macos")]
    pf_token: Option<String>,
}

pub fn prepare(
    ifname: &str,
    source_networks: &[Ipv4Net],
    advertised: bool,
) -> Result<Option<GatewayGuard>> {
    if !advertised {
        return Ok(None);
    }
    #[cfg(target_os = "windows")]
    if source_networks.is_empty() || source_networks.iter().any(|net| net.prefix_len() == 0) {
        bail!("gateway requires explicit non-default mesh source prefixes");
    }
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    {
        let uplink =
            crate::underlay::default_uplink_name(ifname).context("gateway uplink unavailable")?;
        if uplink == ifname {
            bail!("gateway uplink is the Tunnet interface");
        }
        #[cfg(target_os = "windows")]
        if [ifname, uplink.as_str()]
            .iter()
            .any(|name| name.contains(['*', '?', '[', ']']))
        {
            bail!("Windows gateway requires exact interface aliases");
        }
        let mut guard = GatewayGuard::new();
        if let Err(error) = guard.install(ifname, &uplink, source_networks) {
            if let Err(rollback) = guard.teardown() {
                return Err(error.context(format!("gateway rollback failed: {rollback:#}")));
            }
            return Err(error);
        }
        Ok(Some(guard))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = (ifname, source_networks);
        bail!("native gateway configuration is unsupported on this platform")
    }
}

impl GatewayGuard {
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    fn new() -> Self {
        Self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            forwarding: Vec::new(),
            #[cfg(target_os = "linux")]
            table: None,
            #[cfg(target_os = "windows")]
            nat: None,
            #[cfg(target_os = "macos")]
            forwarding: None,
            #[cfg(target_os = "macos")]
            anchor: None,
            #[cfg(target_os = "macos")]
            pf_token: None,
        }
    }

    #[cfg(target_os = "linux")]
    fn install(&mut self, ifname: &str, uplink: &str, _networks: &[Ipv4Net]) -> Result<()> {
        for name in [ifname, uplink] {
            validate_interface(name)?;
            let path =
                std::path::PathBuf::from(format!("/proc/sys/net/ipv4/conf/{name}/forwarding"));
            let previous =
                std::fs::read_to_string(&path).context("read IPv4 interface forwarding")?;
            if previous.trim() != "1" {
                std::fs::write(&path, b"1").context("enable IPv4 interface forwarding")?;
                self.forwarding.push((path, previous));
            }
        }
        let table = format!("tunnet_{}", uuid::Uuid::new_v4().simple());
        let script = format!(
            "table ip {table} {{ chain postrouting {{ type nat hook postrouting priority srcnat; policy accept; iifname \"{ifname}\" oifname \"{uplink}\" masquerade; }} }}\n"
        );
        run_input("nft", &["-f", "-"], &script)?;
        self.table = Some(table);
        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn install(&mut self, ifname: &str, uplink: &str, _networks: &[Ipv4Net]) -> Result<()> {
        let mut networks = _networks.to_vec();
        networks.sort();
        networks.dedup();
        let prefix = networks
            .iter()
            .find(|candidate| networks.iter().all(|net| candidate.contains(net)))
            .context(
                "Windows WinNAT requires one internal prefix containing all mesh source networks",
            )?;
        for name in [ifname, uplink] {
            let alias = ps_quote(name);
            let previous = powershell(&format!(
                "$i = @(Get-NetIPInterface -AddressFamily IPv4 -InterfaceAlias '{alias}' -ErrorAction Stop); if ($i.Count -ne 1) {{ throw 'ambiguous IPv4 interface' }}; $i[0].Forwarding.ToString()"
            ))?;
            let previous = previous.trim().to_owned();
            if previous != "Enabled" && previous != "Disabled" {
                bail!("invalid Windows interface forwarding state");
            }
            if previous == "Disabled" {
                powershell(&format!(
                    "Set-NetIPInterface -AddressFamily IPv4 -InterfaceAlias '{alias}' -Forwarding Enabled -ErrorAction Stop"
                ))?;
                self.forwarding.push((name.to_owned(), previous));
            }
        }
        let name = format!("Tunnet-{}", uuid::Uuid::new_v4().simple());
        powershell(&format!(
            "if (@(Get-NetNat -ErrorAction Stop).Count -ne 0) {{ throw 'WinNAT already configured; multiple internal NAT prefixes are unsupported' }}; New-NetNat -Name '{name}' -InternalIPInterfaceAddressPrefix '{prefix}' -ErrorAction Stop | Out-Null"
        ))?;
        self.nat = Some(name);
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn install(&mut self, ifname: &str, uplink: &str, _networks: &[Ipv4Net]) -> Result<()> {
        validate_interface(ifname)?;
        validate_interface(uplink)?;
        let rules = run("pfctl", &["-sn"])?;
        let filters = run("pfctl", &["-sr"])?;
        if !rules.contains("nat-anchor \"com.apple/*\"")
            || !filters.contains("anchor \"com.apple/*\"")
        {
            bail!("macOS PF configuration lacks the com.apple/* NAT anchor");
        }
        let previous = run("sysctl", &["-n", "net.inet.ip.forwarding"])?;
        if previous.trim() != "1" {
            run("sysctl", &["-w", "net.inet.ip.forwarding=1"])?;
            self.forwarding = Some(previous.trim().to_owned());
        }
        let tag = format!("tn{}", uuid::Uuid::new_v4().simple());
        let anchor = format!("com.apple/{tag}");
        let rules = format!(
            "nat on {uplink} inet from any to any tagged {tag} -> ({uplink})\npass in on {ifname} inet from any to any tag {tag}\n"
        );
        run_input("pfctl", &["-a", &anchor, "-f", "-"], &rules)?;
        self.anchor = Some(anchor);
        let output = run("pfctl", &["-E"])?;
        let token = output
            .lines()
            .find_map(|line| line.trim().strip_prefix("Token : "))
            .context("PF enable returned no ownership token")?;
        self.pf_token = Some(token.trim().to_owned());
        Ok(())
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    pub fn teardown(&mut self) -> Result<()> {
        let mut failures: Vec<anyhow::Error> = Vec::new();
        #[cfg(target_os = "linux")]
        {
            if let Some(table) = &self.table {
                match run("nft", &["delete", "table", "ip", table]) {
                    Ok(_) => self.table = None,
                    Err(error) => failures.push(error),
                }
            }
            self.forwarding.retain(|(path, previous)| {
                let result = std::fs::read_to_string(path).and_then(|current| {
                    if current.trim() == "1" {
                        std::fs::write(path, previous)
                    } else {
                        Ok(())
                    }
                });
                if let Err(error) = result {
                    failures.push(error.into());
                    true
                } else {
                    false
                }
            });
        }
        #[cfg(target_os = "windows")]
        {
            if let Some(name) = &self.nat {
                match powershell(&format!(
                    "Remove-NetNat -Name '{name}' -Confirm:$false -ErrorAction Stop"
                )) {
                    Ok(_) => self.nat = None,
                    Err(error) => failures.push(error),
                }
            }
            self.forwarding.retain(|(name, previous)| {
                let alias = ps_quote(name);
                match powershell(&format!("$i = Get-NetIPInterface -AddressFamily IPv4 -InterfaceAlias '{alias}' -ErrorAction Stop; if ($i.Forwarding -eq 'Enabled') {{ Set-NetIPInterface -AddressFamily IPv4 -InterfaceAlias '{alias}' -Forwarding {previous} -ErrorAction Stop }}")) {
                    Ok(_) => false,
                    Err(error) => { failures.push(error); true }
                }
            });
        }
        #[cfg(target_os = "macos")]
        {
            if let Some(anchor) = &self.anchor {
                match run("pfctl", &["-a", anchor, "-F", "all"]) {
                    Ok(_) => self.anchor = None,
                    Err(error) => failures.push(error),
                }
            }
            if let Some(token) = &self.pf_token {
                match run("pfctl", &["-X", token]) {
                    Ok(_) => self.pf_token = None,
                    Err(error) => failures.push(error),
                }
            }
            if let Some(previous) = &self.forwarding {
                let result = run("sysctl", &["-n", "net.inet.ip.forwarding"]).and_then(|current| {
                    if current.trim() == "1" {
                        run(
                            "sysctl",
                            &["-w", &format!("net.inet.ip.forwarding={previous}")],
                        )
                    } else {
                        Ok(String::new())
                    }
                });
                match result {
                    Ok(_) => self.forwarding = None,
                    Err(error) => failures.push(error),
                }
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            bail!("gateway cleanup failed: {failures:?}")
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    pub fn teardown(&mut self) -> Result<()> {
        Ok(())
    }
}

impl Drop for GatewayGuard {
    fn drop(&mut self) {
        if let Err(error) = self.teardown() {
            tracing::error!(%error, "gateway cleanup failed");
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn validate_interface(name: &str) -> Result<()> {
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-.:".contains(&byte))
    {
        bail!("unsupported interface name");
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn run(program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("launch {program}"))?;
    if !output.status.success() {
        bail!(
            "{program} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn run_input(program: &str, args: &[&str], input: &str) -> Result<()> {
    use std::io::Write;
    use std::process::Stdio;
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .context("command stdin missing")?
        .write_all(input.as_bytes())?;
    let output = child.wait_with_output()?;
    if !output.status.success() {
        bail!(
            "{program} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn ps_quote(value: &str) -> String {
    value.replace('\'', "''")
}

#[cfg(target_os = "windows")]
fn powershell(script: &str) -> Result<String> {
    use std::os::windows::process::CommandExt;
    let output = Command::new("powershell")
        .creation_flags(0x0800_0000)
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &format!("$ErrorActionPreference = 'Stop'; {script}"),
        ])
        .output()?;
    if !output.status.success() {
        bail!(
            "PowerShell failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8(output.stdout)?)
}
