import { describe, expect, test } from "bun:test";
import { create, toBinary } from "@bufbuild/protobuf";

import {
  DataPlane,
  Lifecycle,
  NetworkSchema,
  SnapshotSchema,
} from "@/generated/tunnet/agent_pb";
import { decodeRuntimeSnapshot } from "@/lib/tunnet-runtime";

describe("decodeRuntimeSnapshot", () => {
  test("decodes the canonical protobuf wire format", () => {
    const snapshot = create(SnapshotSchema, {
      lifecycle: Lifecycle.RUNNING,
      dataPlane: DataPlane.UP,
      hostname: "test-device",
      networks: [
        create(NetworkSchema, {
          networkId: "network-id",
          networkName: "test-network",
          ip: "10.9.0.2",
        }),
      ],
    });

    const decoded = decodeRuntimeSnapshot(toBinary(SnapshotSchema, snapshot));

    expect(decoded.lifecycle).toBe(Lifecycle.RUNNING);
    expect(decoded.dataPlane).toBe(DataPlane.UP);
    expect(decoded.hostname).toBe("test-device");
    expect(decoded.networks[0]?.networkId).toBe("network-id");
  });
});
