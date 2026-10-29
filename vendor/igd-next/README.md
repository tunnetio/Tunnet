## Internet Gateway Device client

This is a simple library that communicates with an UPNP enabled gateway device (a router). Contributions and feedback are welcome.
At the moment, you can search for the gateway, request the gateway's external address and, add/remove port mappings. See the `examples/` folder for a demo.

Contributions are welcome! This is pretty delicate to test, please submit an issue if you have trouble using this.

* [Documentation](https://docs.rs/igd-next/)
* [Repository](https://github.com/dariusc93/rust-igd)
* [Crates.io](https://crates.io/crates/igd-next)

## Feature flags

By default the crate uses synchronous IO, using [`attohttpc`](https://crates.io/crates/attohttpc/) as its HTTP client.
The crate also ships an async implementation that uses `tokio` and `hyper`. To use it, disable `default-features` and 
enable the `aio_tokio` feature.

Enable `ipv6` to use IPv6 firewall pinholes. Use `search_ipv6_firewall_gateway` with
`SearchOptions::ipv6(scope_id)` to find the firewall service even when the gateway has no WAN
connection service. The Tokio version is available through `aio::tokio`.

## License
MIT
