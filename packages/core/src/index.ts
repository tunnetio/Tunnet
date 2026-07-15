import {
  type EnrollConfig,
  type EnrollResult,
  TunTunNode as NativeNode,
  type NodeConfig,
  enroll as nativeEnroll,
  type PeerJs,
} from "@tuntundev/sdk";

export type { EnrollConfig, EnrollResult, NodeConfig, PeerJs as Peer };

export interface CreateNodeOptions extends NodeConfig {
  /** Control plane URL (post-enrolment). Falls back to `CONTROL_PLANE_URL`. */
  controlUrl?: string;
  /** Management API URL for API-key enrolment. Falls back to `MANAGEMENT_URL`. */
  managementUrl?: string;
  apiKey?: string;
  organizationId?: string;
  networkId?: string;
  processName?: string;
  runtime?: string;
}

function mapCreateOptions(config: CreateNodeOptions = {}): NodeConfig {
  return {
    stateDir: config.stateDir ?? config.state_dir,
    hostname: config.hostname,
    pollSecs: config.pollSecs ?? config.poll_secs,
    standalone: config.standalone,
    controlUrl: config.controlUrl ?? config.control_url,
    managementUrl: config.managementUrl ?? config.management_url,
    apiKey: config.apiKey ?? config.api_key,
    organizationId: config.organizationId ?? config.organization_id,
    networkId: config.networkId ?? config.network_id,
    processName: config.processName ?? config.process_name,
    runtime: config.runtime,
  };
}

/** One-shot enrolment - persist identity and initial routing snapshot to `state_dir`. */
export async function enroll(config: EnrollConfig): Promise<EnrollResult> {
  return nativeEnroll(config);
}

/** A duplex byte stream over the overlay network. */
export class TunTunStream {
  constructor(
    private readonly inner: InstanceType<
      typeof NativeNode
    >["openStream"] extends (...a: any[]) => Promise<infer T>
      ? T
      : never,
  ) {}

  /** Read up to `maxLen` bytes. Empty Buffer means EOF. */
  read(maxLen = 64 * 1024): Promise<Buffer> {
    return (this.inner as any).read(maxLen);
  }
  /** Write all bytes. */
  write(data: Uint8Array): Promise<void> {
    return (this.inner as any).write(Buffer.from(data));
  }
  /** Close the send side. */
  end(): Promise<void> {
    return (this.inner as any).end();
  }

  /** Convenience: convert to a Web `ReadableStream<Uint8Array>`. */
  toReadableStream(): ReadableStream<Uint8Array> {
    const self = this;
    return new ReadableStream<Uint8Array>({
      async pull(controller) {
        const buf = await self.read();
        if (buf.byteLength === 0) {
          controller.close();
          return;
        }
        controller.enqueue(new Uint8Array(buf));
      },
      async cancel() {
        await self.end().catch(() => {});
      },
    });
  }

  /** Convenience: WritableStream sink that writes into this duplex. */
  toWritableStream(): WritableStream<Uint8Array> {
    const self = this;
    return new WritableStream<Uint8Array>({
      async write(chunk) {
        await self.write(chunk);
      },
      async close() {
        await self.end();
      },
      async abort() {
        await self.end().catch(() => {});
      },
    });
  }
}

/**
 * A handle to the overlay network from a single process. Multiple processes
 * on the same machine share one iroh endpoint through the coordinator UDS -
 * one process becomes coordinator, others become clients transparently.
 */
export class TunTunNode {
  private constructor(
    private readonly native: InstanceType<typeof NativeNode>,
  ) {}

  static async create(config: CreateNodeOptions = {}): Promise<TunTunNode> {
    const native = await NativeNode.create(mapCreateOptions(config));
    return new TunTunNode(native);
  }

  /** Our endpoint id, or empty string if we're a client of the coordinator. */
  get endpointId(): string {
    return this.native.endpointId();
  }

  get isCoordinator(): boolean {
    return this.native.isCoordinator();
  }

  async listPeers(): Promise<PeerJs[]> {
    return this.native.listPeers();
  }

  /**
   * Open a duplex stream to `host:port` where `host` may be a peer's overlay
   * IP (`10.7.0.5`), hostname (`api-prod`), or endpoint id (64-char hex).
   */
  async openStream(host: string, port: number): Promise<TunTunStream> {
    const inner = await this.native.openStream(host, port);
    return new TunTunStream(inner as any);
  }

  /**
   * Convenience: perform an HTTP request to a peer via the overlay by
   * upgrading a stream and speaking HTTP/1.1 manually.
   *
   * For non-trivial HTTP semantics, wire the stream into your favourite
   * HTTP client instead - most support custom transports.
   */
  async fetch(
    url: string,
    init: {
      method?: string;
      headers?: Record<string, string>;
      body?: Uint8Array;
    } = {},
  ): Promise<{
    status: number;
    headers: Record<string, string>;
    body: Uint8Array;
  }> {
    const u = new URL(url);
    const port = u.port ? Number(u.port) : u.protocol === "https:" ? 443 : 80;
    const stream = await this.openStream(u.hostname, port);

    const method = init.method ?? "GET";
    const headers: Record<string, string> = {
      Host: u.host,
      "User-Agent": "tuntun-sdk/0.3",
      Connection: "close",
      ...(init.headers ?? {}),
    };
    if (init.body) headers["Content-Length"] = String(init.body.byteLength);

    let req = `${method} ${u.pathname}${u.search} HTTP/1.1\r\n`;
    for (const [k, v] of Object.entries(headers)) req += `${k}: ${v}\r\n`;
    req += "\r\n";
    await stream.write(new TextEncoder().encode(req));
    if (init.body) await stream.write(init.body);
    await stream.end();

    // Read the whole response.
    const chunks: Uint8Array[] = [];
    for (;;) {
      const buf = await stream.read(64 * 1024);
      if (buf.byteLength === 0) break;
      chunks.push(new Uint8Array(buf));
    }
    const total = chunks.reduce((a, c) => a + c.byteLength, 0);
    const merged = new Uint8Array(total);
    let off = 0;
    for (const c of chunks) {
      merged.set(c, off);
      off += c.byteLength;
    }

    // Split headers/body at CRLFCRLF.
    const sepIdx = indexOfSeq(merged, [13, 10, 13, 10]);
    if (sepIdx < 0) throw new Error("malformed HTTP response");
    const head = new TextDecoder().decode(merged.subarray(0, sepIdx));
    const body = merged.subarray(sepIdx + 4);
    const lines = head.split("\r\n");
    const status = Number(lines[0]?.split(" ")[1] ?? "0");
    const respHeaders: Record<string, string> = {};
    for (let i = 1; i < lines.length; i++) {
      const line = lines[i];
      const colon = line.indexOf(":");
      if (colon > 0)
        respHeaders[line.slice(0, colon).toLowerCase()] = line
          .slice(colon + 1)
          .trim();
    }
    return { status, headers: respHeaders, body };
  }

  async close(): Promise<void> {
    await this.native.close();
  }

  /** Send a local file or directory to a mesh peer. */
  async sendFile(
    path: string,
    target: string,
    message?: string,
  ): Promise<TransferInfo[]> {
    return (this.native as any).sendFile(path, target, message);
  }

  /** Accept a pending inbound offer (prompt consent). */
  async acceptTransfer(transferId: string): Promise<TransferInfo> {
    return (this.native as any).acceptTransfer(transferId);
  }

  /** Reject a pending inbound offer. */
  async rejectTransfer(transferId: string, reason?: string): Promise<void> {
    await (this.native as any).rejectTransfer(transferId, reason);
  }

  /** Pending inbound offers waiting for accept/reject. */
  async listPendingTransfers(): Promise<TransferInfo[]> {
    return (this.native as any).listPendingTransfers();
  }

  /** Active + pending transfers. */
  async listTransfers(): Promise<TransferInfo[]> {
    return (this.native as any).listTransfers();
  }

  /**
   * Poll for new pending file offers. Returns an unsubscribe function.
   */
  onFileOffer(
    callback: (offer: TransferInfo) => void,
    intervalMs = 1000,
  ): () => void {
    const seen = new Set<string>();
    const timer = setInterval(() => {
      void this.listPendingTransfers()
        .then((pending) => {
          for (const p of pending) {
            if (!seen.has(p.transferId)) {
              seen.add(p.transferId);
              callback(p);
            }
          }
        })
        .catch(() => {});
    }, intervalMs);
    return () => clearInterval(timer);
  }
}

export type TransferInfo = {
  transferId: string;
  direction: string;
  peerEndpointId: string;
  peerHostname?: string | null;
  fileName: string;
  size: number | bigint;
  hash: string;
  status: string;
  percent: number;
  bytesTransferred: number | bigint;
  message?: string | null;
  error?: string | null;
  inboxPath?: string | null;
  isDirectory: boolean;
};

function indexOfSeq(haystack: Uint8Array, needle: number[]): number {
  outer: for (let i = 0; i <= haystack.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) continue outer;
    }
    return i;
  }
  return -1;
}
