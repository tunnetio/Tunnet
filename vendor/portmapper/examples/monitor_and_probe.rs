//! Monitor network changes and probe the default route interface for port mapping support.
//!
//! This example demonstrates how to use `netwatch` and `portmapper` to:
//! - Monitor network interface state changes
//! - Detect the current default route interface
//! - Probe for port mapping protocol support (NAT-PMP, PCP, UPnP)

use n0_error::Result;
use n0_future::StreamExt;
use n0_watcher::{self, Watcher};

#[tokio::main]
async fn main() -> Result<()> {
    println!("\nprobe example!\n");

    let monitor = netwatch::netmon::Monitor::new()
        .await
        .expect("failed to create netmon::Monitor");

    let mut stream = monitor.interface_state().stream_updates_only();
    let pm = portmapper::Client::new(portmapper::Config::default());

    let mut should_probe = false;

    loop {
        tokio::select! {
            biased;
            // Monitor for network interface state changes
            state = stream.next() => {
                should_probe = false;

                let Some(state) = state else {
                    // Stream has ended due to underlying actor shutting down
                    break;
                };

                // Skip if no default route is currently active
                let Some(default_route_interface_name) = state.default_route_interface else {
                    continue;
                };

                if let Some(default_route_interface) = state.interfaces.get(&default_route_interface_name) {
                    println!(
                        "\ndefault route interface: {}",
                        default_route_interface.name()
                    );
                    // Display the current network addresses for this interface
                    default_route_interface.addrs().for_each(|addr| {
                        match addr {
                            netwatch::interfaces::IpNet::V4(ipv4_net) => println!("\tipv4: {}", ipv4_net),
                            netwatch::interfaces::IpNet::V6 { net, .. } => println!("\tipv6: {}", net),
                        };
                    });
                    should_probe = true;
                }
            },
            // Probe the current default route interface for port mapping protocol support
            res = pm.probe(), if should_probe => {
                should_probe = false;
                print!("port mapping: ");
                match res {
                    Ok(Ok(res)) => {
                        match (res.nat_pmp, res.pcp, res.upnp) {
                            (false, false, false) => println!("none"),
                            _ => println!("{:?}", res),
                        }},
                    Ok(Err(e)) => eprintln!("portmapper probe error: {e}"),
                    Err(e) => eprintln!("recv error: {e}"),
                }
            },
        }
    }
    Ok(())
}
