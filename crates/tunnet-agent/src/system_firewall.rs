use anyhow::Result;

pub fn configure(ifname: &str) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        windows::configure(ifname)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = ifname;
        Ok(())
    }
}

pub fn teardown(ifname: &str) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        windows::teardown(ifname)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = ifname;
        Ok(())
    }
}

#[cfg(target_os = "windows")]
mod windows {
    use anyhow::{Result, bail};
    use std::os::windows::process::CommandExt;
    use std::process::Command;

    fn powershell(script: &str) -> Result<()> {
        let output = Command::new("powershell")
            .creation_flags(0x0800_0000)
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
            .output()?;
        if !output.status.success() {
            bail!(
                "Windows TUN firewall configuration failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(())
    }

    pub fn configure(ifname: &str) -> Result<()> {
        powershell(&configure_script(ifname)?)
    }

    fn configure_script(ifname: &str) -> Result<String> {
        if ifname.contains(['*', '?', '[', ']']) {
            bail!("Windows firewall requires an exact interface alias");
        }
        let alias = ifname.replace('\'', "''");
        let script = format!(
            r#"
$ErrorActionPreference = 'Stop'
$alias = '{alias}'
$owned = 'Tunnet TUN interface policy'
$adapter = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object {{ $_.Name -eq $alias }})
if ($adapter.Count -ne 1) {{ throw 'Tunnet firewall requires one exact adapter' }}
$adapterGuid = [guid]$adapter[0].InterfaceGuid
$created = @()
try {{
  foreach ($direction in @('Inbound', 'Outbound')) {{
    $name = 'Tunnet:' + $alias + ':' + $direction
    $existing = @(Get-NetFirewallRule -ErrorAction Stop | Where-Object {{ $_.Name -eq $name }})
    if ($existing.Count -ne 0) {{
      if ($existing.Count -ne 1 -or $existing[0].Description -ne $owned) {{ throw 'Tunnet firewall name is owned by another configuration' }}
      $interfaces = @($existing[0] | Get-NetFirewallInterfaceFilter -ErrorAction Stop)
      if ($existing[0].Enabled -ne 'True' -or $existing[0].Direction -ne $direction -or $existing[0].Action -ne 'Allow' -or $existing[0].Profile -ne 'Any') {{ throw 'Tunnet firewall rule changed externally' }}
      if ($interfaces.Count -ne 1 -or @($interfaces[0].InterfaceAlias).Count -ne 1) {{ throw 'Tunnet firewall interface ownership mismatch' }}
      $scope = [string]$interfaces[0].InterfaceAlias
      if ($scope -ne $alias) {{
        $scopeGuid = [guid]::Empty
        if (-not [guid]::TryParse($scope, [ref]$scopeGuid)) {{ throw 'Tunnet firewall interface ownership mismatch' }}
        if ($scopeGuid -ne $adapterGuid) {{
          $live = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object {{ [guid]$_.InterfaceGuid -eq $scopeGuid }})
          if ($live.Count -ne 0) {{ throw 'Tunnet firewall interface ownership mismatch' }}
          $interfaces[0] | Set-NetFirewallInterfaceFilter -InterfaceAlias $alias -ErrorAction Stop | Out-Null
        }}
      }}
    }} else {{
      New-NetFirewallRule -Name $name -DisplayName $name -Description $owned -Direction $direction -Action Allow -Profile Any -InterfaceAlias $alias -ErrorAction Stop | Out-Null
      $created += $name
    }}
  }}
}} catch {{
  $failure = $_
  foreach ($name in $created) {{ Get-NetFirewallRule -ErrorAction Stop | Where-Object {{ $_.Name -eq $name }} | Remove-NetFirewallRule -ErrorAction Stop }}
  throw $failure
}}
"#
        );
        Ok(script)
    }

    pub fn teardown(ifname: &str) -> Result<()> {
        let alias = ifname.replace('\'', "''");
        powershell(&format!(
            r#"
$ErrorActionPreference = 'Stop'
foreach ($name in @('Tunnet:{alias}:Inbound', 'Tunnet:{alias}:Outbound')) {{
  $rule = Get-NetFirewallRule -ErrorAction Stop | Where-Object {{ $_.Name -eq $name }}
  if ($null -ne $rule) {{
    if ($rule.Description -ne 'Tunnet TUN interface policy') {{ throw 'Tunnet firewall rule ownership mismatch' }}
    $rule | Remove-NetFirewallRule -ErrorAction Stop
  }}
}}
"#
        ))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[rstest::rstest]
        #[case("tunnet0", false, true, 0)]
        #[case("11111111-1111-1111-1111-111111111111", false, true, 0)]
        #[case("22222222-2222-2222-2222-222222222222", false, true, 2)]
        #[case("22222222-2222-2222-2222-222222222222", true, false, 0)]
        #[case("other", false, false, 0)]
        #[case("Any", false, false, 0)]
        fn firewall_scope_recovery(
            #[case] scope: &str,
            #[case] live: bool,
            #[case] allowed: bool,
            #[case] updates: usize,
        ) {
            let live = if live { "$true" } else { "$false" };
            let script = format!(
                r#"
$script:updates = 0
function Get-NetAdapter {{
  [pscustomobject]@{{ Name='tunnet0'; InterfaceGuid='11111111-1111-1111-1111-111111111111' }}
  if ({live}) {{ [pscustomobject]@{{ Name='other'; InterfaceGuid='22222222-2222-2222-2222-222222222222' }} }}
}}
function Get-NetFirewallRule {{
  foreach ($direction in @('Inbound', 'Outbound')) {{
    [pscustomobject]@{{ Name=('Tunnet:tunnet0:' + $direction); Description='Tunnet TUN interface policy'; Enabled='True'; Direction=$direction; Action='Allow'; Profile='Any' }}
  }}
}}
function Get-NetFirewallInterfaceFilter {{ process {{ [pscustomobject]@{{ InterfaceAlias='{scope}' }} }} }}
function Set-NetFirewallInterfaceFilter {{ param($InterfaceAlias) process {{
  if ($InterfaceAlias -ne 'tunnet0') {{ throw 'unexpected scope' }}
  $script:updates++
}} }}
{configure}
if ($script:updates -ne {updates}) {{ throw 'incorrect scope update count' }}
"#,
                configure = configure_script("tunnet0").unwrap(),
            );
            assert_eq!(powershell(&script).is_ok(), allowed);
        }
    }
}
