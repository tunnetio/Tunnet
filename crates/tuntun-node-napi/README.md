# @tuntundev/sdk

Native bindings for [TunTun](https://github.com/orielhaim/TunTun) - join a machine to your private overlay network from JavaScript or TypeScript.

Use this package to enroll an SDK node, connect to the mesh, list peers, and open byte streams to services on other machines.

## Install

```bash
npm install @tuntundev/sdk
# or
bun add @tuntundev/sdk
```

## Quick start

### Enroll with an API key

Create an API key in the TunTun dashboard with the `sdk:enroll` scope, then enroll once:

```ts
import { enroll, TunTunNode } from "@tuntundev/sdk";

const result = await enroll({
  controlUrl: "https://control.example.com",
  managementUrl: "https://api.example.com",
  apiKey: process.env.TUNTUN_API_KEY!,
  organizationId: "your-org-id",
  networkId: "your-network-id",
  hostname: "my-app",
});

console.log(result.endpointId, result.ip, result.network);

const node = await TunTunNode.create({
  controlUrl: "https://control.example.com",
});

const peers = await node.listPeers();
console.log(peers);
```

### Enroll with a one-time token

```ts
import { enroll, TunTunNode } from "@tuntundev/sdk";

await enroll({
  controlUrl: "https://control.example.com",
  token: "YOUR_ENROLLMENT_TOKEN",
});

const node = await TunTunNode.create({
  controlUrl: "https://control.example.com",
});
```

After the first enroll, identity and state are persisted under your state directory. Later `TunTunNode.create()` calls reuse them without passing credentials again.

### Open a stream to a peer

`host` can be a peer overlay IP, hostname, or endpoint id:

```ts
const stream = await node.openStream("10.64.0.5", 8080);

const chunk = await stream.read(4096);
await stream.write(Buffer.from("hello"));
await stream.end();

await node.close();
```

## Environment variables

| Variable | Purpose |
| --- | --- |
| `CONTROL_PLANE_URL` | Control plane URL (used by `TunTunNode.create()` if not passed in config) |
| `MANAGEMENT_URL` | Management API URL for API-key enrollment |
| `TUNTUN_STATE_DIR` | Directory for persisted identity and state |

If `stateDir` is not set in config, state defaults to the platform XDG/state location.

## API

- `enroll(config)` - one-shot enrollment; persists identity to disk
- `TunTunNode.create(config)` - connect to or start the local overlay node
- `node.endpointId()` - this node's endpoint id (hex)
- `node.isCoordinator()` - whether this process owns the local coordinator
- `node.listPeers()` - peers in the routing table
- `node.openStream(host, port)` - duplex stream to a peer service
- `node.close()` - shut down the node

See `index.d.ts` for full TypeScript types.

## Platforms

Prebuilt binaries are published for:

- Linux (glibc and musl) - x64, arm64
- macOS - x64, arm64
- Windows - x64, arm64

## License

Apache-2.0
