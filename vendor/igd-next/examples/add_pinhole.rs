use std::env;
use std::net::{Ipv6Addr, SocketAddrV6};

extern crate igd_next as igd;

fn main() {
    let args: Vec<_> = env::args().collect();
    if args.len() != 4 {
        println!("Usage add_pinhole <interface_scope_id> <internal_ipv6_address> <internal_port>");
        return;
    }
    let scope_id = args[1].parse::<u32>().expect("Invalid interface scope ID");
    let ip = args[2].parse::<Ipv6Addr>().expect("Invalid IPv6 address");
    let port = args[3].parse::<u16>().expect("Invalid port");
    let internal_client = SocketAddrV6::new(ip, port, 0, 0);

    let gateway = match igd::search_ipv6_firewall_gateway(igd::SearchOptions::ipv6(scope_id)) {
        Ok(gateway) => gateway,
        Err(err) => {
            println!("Failed to find an IPv6 firewall gateway {err}");
            return;
        }
    };

    // Check whether the gateway supports IPv6 pinholes at all.
    match gateway.get_firewall_status() {
        Ok(status) => println!(
            "Firewall enabled: {}, inbound pinholes allowed: {}",
            status.firewall_enabled, status.inbound_pinhole_allowed
        ),
        Err(err) => {
            println!("Could not query firewall status: {err}");
            return;
        }
    }

    // Open a TCP pinhole to the internal client with a one-hour lease (between 1 and 86_400 seconds).
    match gateway.add_pinhole(igd::PortMappingProtocol::TCP, internal_client, 3600) {
        Ok(unique_id) => {
            println!("AddPinhole successful, UniqueID = {unique_id}");

            // Clean up by removing the pinhole we just created.
            match gateway.remove_pinhole(unique_id) {
                Ok(()) => println!("DeletePinhole successful."),
                Err(err) => println!("Error removing pinhole: {err}"),
            }
        }
        Err(err) => println!("AddPinhole failed: {err}"),
    }
}
