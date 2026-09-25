import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { Dispatcher } from "undici";
import { Agent, fetch as undiciFetch } from "undici";
import { type ApiError, type ApiErrorCode, TunnetApiError } from "./types";

type ApiResponse = Awaited<ReturnType<typeof undiciFetch>>;

function isBunRuntime(): boolean {
  return (
    typeof process !== "undefined" &&
    typeof process.versions === "object" &&
    process.versions !== null &&
    "bun" in process.versions
  );
}

const agents = new Map<string, Agent>();

/** Resolve the Local Management API endpoint path (Unix socket or Windows marker). */
export function defaultApiPath(env: NodeJS.ProcessEnv = process.env): string {
  const override = env.TUNNET_API_PATH ?? env.TUNNET_IPC_PATH;
  if (override) return override;

  if (process.platform === "win32") {
    const base = env.PROGRAMDATA ?? "C:\\ProgramData";
    return join(base, "tunnet", "ipc", "tunnetd.pipe");
  }

  if (env.TUNNET_RUNTIME_DIR) {
    return join(env.TUNNET_RUNTIME_DIR, "tunnetd.sock");
  }

  if (existsSync("/run/tunnet")) {
    return "/run/tunnet/tunnetd.sock";
  }
  return join("/tmp", "tunnetd.sock");
}

/** Resolve the connection target for the current platform. */
export function resolveConnectPath(endpointPath: string): string {
  if (process.platform !== "win32") {
    return endpointPath;
  }

  const candidates = [
    endpointPath,
    join(
      process.env.PROGRAMDATA ?? "C:\\ProgramData",
      "tunnet",
      "ipc",
      "tunnetd.pipe",
    ),
  ];

  for (const candidate of candidates) {
    try {
      const name = readFileSync(candidate, "utf8").trim();
      if (name) return name;
    } catch {
      // try next candidate
    }
  }

  return "\\\\.\\pipe\\tunnetd";
}

function getAgent(connectPath: string): Agent {
  let agent = agents.get(connectPath);
  if (!agent) {
    agent = new Agent({
      allowH2: false,
      connect: { socketPath: connectPath },
    });
    agents.set(connectPath, agent);
  }
  return agent;
}

function localUrl(path: string): string {
  return `http://localhost${path.startsWith("/") ? path : `/${path}`}`;
}

export interface ApiFetchInit extends Omit<RequestInit, "body" | "headers"> {
  body?: unknown;
  dispatcher?: Dispatcher;
  headers?: Record<string, string>;
}

export async function apiFetch(
  endpointPath: string,
  path: string,
  init: ApiFetchInit = {},
): Promise<ApiResponse> {
  const connectPath = resolveConnectPath(endpointPath);
  const url = localUrl(path);
  const { body, dispatcher, headers, method, signal } = init;

  const requestHeaders: Record<string, string> = { ...headers };
  let requestBody: string | undefined;

  if (body !== undefined) {
    requestHeaders["content-type"] = "application/json";
    requestBody = JSON.stringify(body);
  }

  if (isBunRuntime()) {
    return fetch(url, {
      method,
      signal,
      headers: requestHeaders,
      body: requestBody,
      unix: connectPath,
    } as RequestInit) as unknown as ApiResponse;
  }

  return undiciFetch(url, {
    method,
    signal,
    headers: requestHeaders,
    body: requestBody,
    dispatcher: dispatcher ?? getAgent(connectPath),
  });
}

export async function readApiJson<T>(
  endpointPath: string,
  path: string,
  init: ApiFetchInit = {},
): Promise<T> {
  let response: ApiResponse;
  try {
    response = await apiFetch(endpointPath, path, init);
  } catch {
    throw new TunnetApiError("daemon_not_running", "");
  }

  const text = await response.text();
  if (response.status < 200 || response.status >= 300) {
    throw parseApiFailure(response.status, text, init.method ?? "GET", path);
  }

  try {
    return JSON.parse(text) as T;
  } catch {
    throw new Error(
      `decode Local API response for ${init.method ?? "GET"} ${path}: ${text}`,
    );
  }
}

export function parseApiFailure(
  status: number,
  text: string,
  method: string,
  path: string,
): Error {
  try {
    const err = JSON.parse(text) as ApiError;
    if (err.code && err.message !== undefined) {
      return new TunnetApiError(err.code, err.message);
    }
  } catch {
    // fall through
  }

  return new Error(`Local API ${method} ${path} failed (${status}): ${text}`);
}

export function networkQuery(base: string, network?: string): string {
  if (!network) return base;
  return `${base}?network=${encodeURIComponent(network)}`;
}

export async function* parseEventsSse(
  body: { getReader(): ReadableStreamDefaultReader<Uint8Array> } | null,
): AsyncGenerator<import("./types").LocalEvent> {
  if (!body) return;

  const reader = body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });

    const blocks = buffer.split("\n\n");
    buffer = blocks.pop() ?? "";

    for (const block of blocks) {
      for (const line of block.split("\n")) {
        if (!line.startsWith("data:")) continue;
        const data = line.slice(5).trim();
        if (!data) continue;

        try {
          yield JSON.parse(data) as import("./types").LocalEvent;
        } catch {
          try {
            const err = JSON.parse(data) as ApiError;
            throw new TunnetApiError(err.code as ApiErrorCode, err.message);
          } catch (inner) {
            if (inner instanceof TunnetApiError) throw inner;
          }
        }
      }
    }
  }
}

export async function* parsePingSse(
  body: { getReader(): ReadableStreamDefaultReader<Uint8Array> } | null,
): AsyncGenerator<import("./types").PingEvent> {
  if (!body) return;

  const reader = body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });

    const blocks = buffer.split("\n\n");
    buffer = blocks.pop() ?? "";

    for (const block of blocks) {
      for (const line of block.split("\n")) {
        if (!line.startsWith("data:")) continue;
        const data = line.slice(5).trim();
        if (!data) continue;

        try {
          const event = JSON.parse(data) as import("./types").PingEvent;
          yield event;
          if (event.type === "summary") return;
        } catch {
          try {
            const err = JSON.parse(data) as ApiError;
            throw new TunnetApiError(err.code as ApiErrorCode, err.message);
          } catch (inner) {
            if (inner instanceof TunnetApiError) throw inner;
          }
        }
      }
    }
  }
}
