import { z } from "zod";

import { deviceStatusSchema } from "./common";

export const deviceMetadataSchema = z
  .object({
    hostname: z.string(),
    os: z.string(),
    osVersion: z.string().optional(),
    arch: z.string().optional(),
    family: z.string().optional(),
    agentVersion: z.string().optional(),
    cpuCount: z.number().int().nonnegative().optional(),
    totalMemoryBytes: z.number().int().nonnegative().optional(),
    reportedAt: z.string().optional(),
  })
  .catchall(z.unknown());

export const deviceMembershipSchema = z.object({
  networkId: z.string().uuid(),
  networkName: z.string(),
  assignedIp: z.string(),
  status: deviceStatusSchema,
  firstSeen: z.string().datetime(),
  lastSeen: z.string().datetime(),
});

export const deviceSchema = z.object({
  endpointId: z.string().length(64),
  organizationId: z.string(),
  networkId: z.string().uuid(),
  name: z.string(),
  hostname: z.string(),
  type: z.enum(["agent", "sdk"]),
  os: z.string().nullable(),
  agentVersion: z.string().nullable(),
  assignedIp: z.string(),
  publicIp: z.string().nullable(),
  ipv6Enabled: z.boolean(),
  tenantIpv6: z.string().nullable(),
  agentConnected: z.boolean(),
  connectedAt: z.string().datetime().nullable(),
  disconnectedAt: z.string().datetime().nullable(),
  lastHeartbeatAt: z.string().datetime().nullable(),
  firstSeen: z.string().datetime(),
  lastSeen: z.string().datetime(),
  status: deviceStatusSchema,
});

export const deviceDetailSchema = z.object({
  endpointId: z.string().length(64),
  organizationId: z.string(),
  name: z.string(),
  metadata: deviceMetadataSchema,
  publicIp: z.string().nullable(),
  ipv6Enabled: z.boolean(),
  ipv6EnabledAt: z.string().datetime().nullable(),
  tenantIpv6: z.string(),
  agentConnected: z.boolean(),
  connectedAt: z.string().datetime().nullable(),
  disconnectedAt: z.string().datetime().nullable(),
  lastHeartbeatAt: z.string().datetime().nullable(),
  firstSeen: z.string().datetime(),
  lastSeen: z.string().datetime(),
  memberships: z.array(deviceMembershipSchema),
});

export const patchDeviceBody = z
  .object({
    name: z.string().trim().min(1).max(253).optional(),
    ipv6Enabled: z.boolean().optional(),
  })
  .refine((body) => body.name !== undefined || body.ipv6Enabled !== undefined, {
    message: "At least one field must be provided",
  });

export const patchDeviceMembershipBody = z.object({
  status: deviceStatusSchema,
});

export const deviceListResponse = z.object({
  devices: z.array(deviceSchema),
});

export const deleteDeviceItemSchema = z.object({
  networkId: z.string().uuid(),
  endpointId: z.string().length(64),
});

export const deleteDevicesBody = z.object({
  items: z.array(deleteDeviceItemSchema).min(1).max(100),
});

export const deleteDevicesResponse = z.object({
  ok: z.literal(true),
  deleted: z.number().int().nonnegative(),
});

export type DeleteDeviceItem = z.infer<typeof deleteDeviceItemSchema>;
export type DeleteDevicesBody = z.infer<typeof deleteDevicesBody>;
export type DeleteDevicesResponse = z.infer<typeof deleteDevicesResponse>;

export type DeviceMetadata = z.infer<typeof deviceMetadataSchema>;
export type DeviceMembership = z.infer<typeof deviceMembershipSchema>;
export type Device = z.infer<typeof deviceSchema>;
export type DeviceDetail = z.infer<typeof deviceDetailSchema>;
export type PatchDeviceBody = z.infer<typeof patchDeviceBody>;
export type PatchDeviceMembershipBody = z.infer<
  typeof patchDeviceMembershipBody
>;
