use igd_next as igd;
use std::env;

fn main() {
    let scope_id: u32 = match env::args().nth(1) {
        Some(arg) => arg.parse().expect("scope id must be the numeric interface zone index"),
        None => {
            println!("Usage: search_ipv6 <interface_scope_id>");
            return;
        }
    };

    match igd::search_gateway(igd::SearchOptions::ipv6(scope_id)) {
        Ok(gateway) => {
            println!("Found gateway: {gateway}");
            match gateway.get_external_ip() {
                Ok(ip) => println!("External IP address: {ip}"),
                Err(err) => println!("Could not get external IP: {err}"),
            }
        }
        Err(err) => println!("Failed to find an IPv6 IGD gateway: {err}"),
    }
}
