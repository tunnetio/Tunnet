#[cfg(any(target_os = "windows", target_os = "linux"))]
mod native {
    use anyhow::{Context, Result, ensure};
    use ipnet::Ipv4Net;
    use route_manager::{Route, RouteManager};
    use serde::Serialize;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::time::Instant;
    use tokio_util::sync::CancellationToken;
    use tun_rs::{AsyncDevice, DeviceBuilder};

    const IFNAME: &str = "tunnet-bench";
    const SOURCE: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 1);
    const TARGET: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 2);
    const PORT: u16 = 47999;
    const BATCH: usize = 64;

    struct OwnedRoute {
        manager: RouteManager,
        route: Option<Route>,
    }

    impl OwnedRoute {
        fn teardown(&mut self) -> Result<()> {
            if let Some(route) = &self.route {
                self.manager
                    .delete(route)
                    .context("delete benchmark route")?;
                self.route = None;
            }
            Ok(())
        }
    }

    impl Drop for OwnedRoute {
        fn drop(&mut self) {
            if let Err(error) = self.teardown() {
                eprintln!("benchmark_route_cleanup_failed={error:#}");
            }
        }
    }

    #[derive(Default, Serialize)]
    struct Capture {
        packets: u64,
        ip_bytes: u64,
        udp_payload_bytes: u64,
        unrelated_packets: u64,
        batches: u64,
        max_batch: usize,
        read_waits: u64,
    }

    impl Capture {
        fn packet(&mut self, packet: &[u8]) {
            if packet.len() >= 28
                && packet[0] >> 4 == 4
                && packet[9] == 17
                && packet[12..16] == SOURCE.octets()
                && packet[16..20] == TARGET.octets()
            {
                let ip_header = usize::from(packet[0] & 15) * 4;
                if packet.len() >= ip_header + 8
                    && u16::from_be_bytes([packet[ip_header + 2], packet[ip_header + 3]]) == PORT
                {
                    self.packets += 1;
                    self.ip_bytes += packet.len() as u64;
                    self.udp_payload_bytes += (packet.len() - ip_header - 8) as u64;
                    return;
                }
            }
            self.unrelated_packets += 1;
        }
    }

    async fn capture(device: Arc<AsyncDevice>, cancel: CancellationToken) -> Result<Capture> {
        let mut result = Capture::default();
        let mut buffer = vec![0; 65536];
        loop {
            let mut count = 0;
            while count < BATCH {
                match device.try_recv(&mut buffer) {
                    Ok(n) if n > 0 => {
                        result.packet(&buffer[..n]);
                        count += 1;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error.into()),
                    Ok(_) => anyhow::bail!("benchmark TUN unexpectedly closed"),
                }
            }
            if count == 0 {
                result.read_waits += 1;
                let n = tokio::select! {
                    biased;
                    _ = cancel.cancelled() => return Ok(result),
                    received = device.recv(&mut buffer) => received?,
                };
                ensure!(n > 0, "benchmark TUN unexpectedly closed");
                result.packet(&buffer[..n]);
                count = 1;
                while count < BATCH {
                    match device.try_recv(&mut buffer) {
                        Ok(n) if n > 0 => {
                            result.packet(&buffer[..n]);
                            count += 1;
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(error) => return Err(error.into()),
                        Ok(_) => anyhow::bail!("benchmark TUN unexpectedly closed"),
                    }
                }
            }
            result.batches += 1;
            result.max_batch = result.max_batch.max(count);
            if cancel.is_cancelled() {
                return Ok(result);
            }
            tokio::task::yield_now().await;
        }
    }

    #[cfg(windows)]
    fn cpu_seconds() -> Result<f64> {
        use windows_sys::Win32::Foundation::FILETIME;
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessTimes};
        let mut creation = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let mut exit = creation;
        let mut kernel = creation;
        let mut user = creation;
        // The output pointers refer to initialized, live FILETIME values.
        if unsafe {
            GetProcessTimes(
                GetCurrentProcess(),
                &mut creation,
                &mut exit,
                &mut kernel,
                &mut user,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        let ticks =
            |time: FILETIME| (u64::from(time.dwHighDateTime) << 32) | u64::from(time.dwLowDateTime);
        Ok((ticks(kernel) + ticks(user)) as f64 / 10_000_000.0)
    }

    #[cfg(target_os = "linux")]
    fn cpu_seconds() -> Result<f64> {
        let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
        // getrusage initializes this value on success.
        if unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let usage = unsafe { usage.assume_init() };
        Ok(usage.ru_utime.tv_sec as f64
            + usage.ru_stime.tv_sec as f64
            + (usage.ru_utime.tv_usec + usage.ru_stime.tv_usec) as f64 / 1_000_000.0)
    }

    #[cfg(windows)]
    async fn wait_address(index: u32) -> Result<()> {
        use windows_sys::Win32::{
            NetworkManagement::IpHelper::{GetUnicastIpAddressEntry, MIB_UNICASTIPADDRESS_ROW},
            Networking::WinSock::{
                AF_INET, IN_ADDR, IN_ADDR_0, IpDadStateDuplicate, IpDadStatePreferred, SOCKADDR_IN,
                SOCKADDR_INET,
            },
        };
        let start = Instant::now();
        let mut previous = None;
        loop {
            let mut row = MIB_UNICASTIPADDRESS_ROW {
                InterfaceIndex: index,
                Address: SOCKADDR_INET {
                    Ipv4: SOCKADDR_IN {
                        sin_family: AF_INET,
                        sin_addr: IN_ADDR {
                            S_un: IN_ADDR_0 {
                                S_addr: u32::from_ne_bytes(SOURCE.octets()),
                            },
                        },
                        ..Default::default()
                    },
                },
                ..Default::default()
            };
            // The row identifies the owned interface and address and remains live for the call.
            let status = unsafe { GetUnicastIpAddressEntry(&mut row) };
            ensure!(
                status == 0,
                "GetUnicastIpAddressEntry({index}, {SOURCE}) status={status}"
            );
            if previous != Some(row.DadState) {
                eprintln!(
                    "native_address_state interface={index} address={SOURCE} dad_state={} elapsed_ms={}",
                    row.DadState,
                    start.elapsed().as_millis()
                );
                previous = Some(row.DadState);
            }
            if row.DadState == IpDadStatePreferred {
                return Ok(());
            }
            ensure!(
                row.DadState != IpDadStateDuplicate,
                "benchmark address is duplicate"
            );
            ensure!(
                start.elapsed() < Duration::from_secs(5),
                "benchmark address did not become preferred; dad_state={}",
                row.DadState
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    pub async fn run() -> Result<()> {
        let args: Vec<String> = std::env::args().collect();
        let option = |key: &str| {
            args.windows(2)
                .find(|pair| pair[0] == key)
                .map(|pair| pair[1].as_str())
        };
        let mbps: u32 = option("--mbps").unwrap_or("100").parse()?;
        let seconds: u32 = option("--seconds").unwrap_or("10").parse()?;
        let size: usize = option("--size").unwrap_or("1100").parse()?;
        ensure!(
            (1..=10000).contains(&mbps)
                && (1..=300).contains(&seconds)
                && (8..=1400).contains(&size),
            "invalid workload; mbps 1..10000, seconds 1..300, UDP size 8..1400"
        );
        ensure!(
            !netdev::get_interfaces()
                .iter()
                .any(|iface| iface.name == IFNAME
                    || iface.friendly_name.as_deref() == Some(IFNAME)
                    || iface
                        .ipv4
                        .iter()
                        .any(|net| net.addr() == SOURCE || net.addr() == TARGET)),
            "benchmark interface or test addresses already in use"
        );
        let mut manager = RouteManager::new()?;
        for route in manager.list()? {
            if let IpAddr::V4(address) = route.destination() {
                let prefix = Ipv4Net::new(address, route.prefix())?;
                ensure!(
                    prefix.prefix_len() == 0
                        || (!prefix.contains(&SOURCE) && !prefix.contains(&TARGET)),
                    "existing route conflicts with benchmark test addresses: {route}"
                );
            }
        }
        let builder = DeviceBuilder::new()
            .name(IFNAME)
            .ipv4(SOURCE, 32, None)
            .mtu(1500);
        #[cfg(windows)]
        let builder = {
            let default = concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/resources/wintun/amd64/wintun.dll"
            );
            let path = option("--wintun").unwrap_or(default);
            ensure!(
                std::path::Path::new(path).is_file(),
                "Wintun DLL not found; specify --wintun PATH"
            );
            builder.wintun_file(path.to_owned())
        };
        let device = Arc::new(
            builder
                .build_async()
                .context("create isolated benchmark TUN")?,
        );
        let route = Route::new(IpAddr::V4(TARGET), 32)
            .with_if_index(device.if_index()?)
            .with_if_name(IFNAME.to_owned())
            .with_metric(1);
        manager
            .add(&route)
            .context("add isolated benchmark host route")?;
        let mut owned = OwnedRoute {
            manager,
            route: Some(route),
        };
        let workload = async {
            #[cfg(windows)]
            wait_address(device.if_index()?).await?;
            let socket = tokio::net::UdpSocket::bind(SocketAddr::from((SOURCE, 0)))
                .await.context("bind benchmark host UDP source")?;
            let cpu_start = cpu_seconds()?;
            let cancel = CancellationToken::new();
            let reader = tokio::spawn(capture(device.clone(), cancel.clone()));
            let mut payload = vec![0x42; size];
            let start = Instant::now();
            let end = start + Duration::from_secs(u64::from(seconds));
            let bytes_per_second = u64::from(mbps) * 125_000;
            let mut accepted = 0u64;
            let send_result: Result<()> = async {
                while Instant::now() < end {
                    for _ in 0..32 {
                        if Instant::now() >= end { break; }
                        payload[..8].copy_from_slice(&accepted.to_be_bytes());
                        ensure!(socket.send_to(&payload, SocketAddr::from((TARGET, PORT))).await? == size, "partial UDP send");
                        accepted += 1;
                    }
                    let target = start + Duration::from_secs_f64(accepted as f64 * size as f64 / bytes_per_second as f64);
                    if target > Instant::now() { tokio::time::sleep_until(target.min(end)).await; }
                    else { tokio::task::yield_now().await; }
                }
                Ok(())
            }.await;
            let send_elapsed = start.elapsed().as_secs_f64();
            tokio::time::sleep(Duration::from_millis(250)).await;
            cancel.cancel();
            let captured = reader.await.context("benchmark reader task")??;
            send_result?;
            let output = serde_json::json!({
                "schema_version": 1, "stage": "native_tun_host_udp_capture", "platform": std::env::consts::OS,
                "interface": IFNAME, "source": SOURCE.to_string(), "target": TARGET.to_string(), "mtu": 1500,
                "receive_strategy": "try_recv_drain_64_then_async_recv", "configured_mbps": mbps,
                "configured_seconds": seconds, "udp_payload_size": size, "host_accepted_datagrams": accepted,
                "host_accepted_payload_bytes": accepted * size as u64, "send_elapsed_seconds": send_elapsed,
                "process_cpu_seconds": cpu_seconds()? - cpu_start, "capture": captured,
                "total_elapsed_seconds": start.elapsed().as_secs_f64(),
                "captured_payload_mbps": captured.udp_payload_bytes as f64 * 8.0 / send_elapsed / 1_000_000.0,
                "host_to_tun_missing_datagrams": accepted.saturating_sub(captured.packets),
                "mean_batch": captured.packets as f64 / captured.batches.max(1) as f64,
                "write_path_measured": false,
            });
            let json = serde_json::to_string_pretty(&output)?;
            if let Some(path) = option("--output") { std::fs::write(path, &json)?; }
            println!("{json}");
            Ok::<_, anyhow::Error>(())
        }.await;
        let cleanup = owned.teardown();
        drop(device);
        cleanup?;
        workload
    }
}

#[cfg(any(target_os = "windows", target_os = "linux"))]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    native::run().await
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
fn main() {
    eprintln!("tun_bench requires Windows or Linux");
}
