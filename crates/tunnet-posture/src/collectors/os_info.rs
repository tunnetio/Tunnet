use crate::collector::{PostureAttributes, PostureCollector};
use crate::error::PostureError;
use crate::platform::Platform;
use crate::value::PostureValue;
use async_trait::async_trait;

pub struct OsCollector {
    tunnet_version: String,
}

impl OsCollector {
    pub fn new(tunnet_version: impl Into<String>) -> Self {
        Self {
            tunnet_version: tunnet_version.into(),
        }
    }
}

impl Default for OsCollector {
    fn default() -> Self {
        Self::new(env!("CARGO_PKG_VERSION"))
    }
}

#[async_trait]
impl PostureCollector for OsCollector {
    fn name(&self) -> &'static str {
        "os_info"
    }

    fn supported_platforms(&self) -> &[Platform] {
        &[
            Platform::Windows,
            Platform::MacOS,
            Platform::Linux,
            Platform::FreeBSD,
        ]
    }

    fn namespace(&self) -> &'static str {
        "node"
    }

    async fn collect(&self) -> Result<PostureAttributes, PostureError> {
        let mut attrs = PostureAttributes::new(self.name());

        let info = os_info::get();
        let os_name = match info.os_type() {
            os_info::Type::Windows => "windows",
            os_info::Type::Macos => "macos",
            os_info::Type::Ubuntu
            | os_info::Type::Debian
            | os_info::Type::Fedora
            | os_info::Type::Redhat
            | os_info::Type::Arch
            | os_info::Type::Manjaro
            | os_info::Type::Linux => "linux",
            os_info::Type::FreeBSD => "freebsd",
            _ => "linux",
        };

        attrs
            .attributes
            .insert("node:os".into(), PostureValue::String(os_name.to_string()));
        attrs.attributes.insert(
            "node:osVersion".into(),
            PostureValue::String(info.version().to_string()),
        );
        attrs.attributes.insert(
            "node:osBuild".into(),
            PostureValue::String(info.edition().map(|e| e.to_string()).unwrap_or_default()),
        );
        attrs.attributes.insert(
            "node:arch".into(),
            PostureValue::String(std::env::consts::ARCH.to_string()),
        );
        attrs.attributes.insert(
            "node:hostname".into(),
            PostureValue::String(whoami::hostname().unwrap_or_default()),
        );
        attrs.attributes.insert(
            "node:tunnetVersion".into(),
            PostureValue::String(self.tunnet_version.clone()),
        );

        let kernel = collect_kernel_version().await;
        attrs
            .attributes
            .insert("node:kernel".into(), PostureValue::String(kernel));

        let uptime = collect_uptime_secs();
        attrs
            .attributes
            .insert("node:uptime".into(), PostureValue::Number(uptime));

        Ok(attrs)
    }
}

async fn collect_kernel_version() -> String {
    #[cfg(unix)]
    {
        if let Some(out) = super::run_command("uname", &["-r"]).await {
            return out;
        }
    }
    #[cfg(windows)]
    {
        if let Some(out) =
            super::run_powershell("(Get-CimInstance Win32_OperatingSystem).Version").await
        {
            return out;
        }
    }
    String::new()
}

fn collect_uptime_secs() -> f64 {
    sysinfo::System::uptime() as f64
}
