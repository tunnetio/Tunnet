import { fromBinary } from "@bufbuild/protobuf";

import { SnapshotSchema } from "@/generated/tunnet/agent_pb";

export function decodeRuntimeSnapshot(bytes: Uint8Array) {
  return fromBinary(SnapshotSchema, bytes);
}
