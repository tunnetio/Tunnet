import { createListenClient } from "@tunnet/db";
import { ENTITY_NOTIFY_CHANNEL, PRESENCE_NOTIFY_CHANNEL } from "./notify";

export type PresenceNotifyHandler = (channel: string, payload: string) => void;

type ListenClient = {
  listen: (
    channel: string,
    onnotify: (payload: string) => void,
  ) => Promise<unknown>;
  end: (options?: { timeout?: number }) => Promise<void>;
};

type CreateListenClient = () => ListenClient;

export class PresenceNotifyHub {
  private readonly listeners = new Set<PresenceNotifyHandler>();
  private startPromise: Promise<void> | null = null;
  private started = false;

  constructor(private readonly createClient: CreateListenClient) {}

  subscribe(handler: PresenceNotifyHandler): () => void {
    this.listeners.add(handler);
    void this.ensureStarted();
    return () => {
      this.listeners.delete(handler);
    };
  }

  private dispatch(channel: string, payload: string): void {
    for (const handler of this.listeners) {
      try {
        handler(channel, payload);
      } catch (error) {
        console.error("[presence] notify handler failed:", error);
      }
    }
  }

  private ensureStarted(): Promise<void> {
    if (this.started) {
      return Promise.resolve();
    }
    if (this.startPromise) {
      return this.startPromise;
    }

    this.startPromise = this.start().finally(() => {
      this.startPromise = null;
    });
    return this.startPromise;
  }

  private async start(): Promise<void> {
    try {
      const client = this.createClient();
      await client.listen(PRESENCE_NOTIFY_CHANNEL, (payload) => {
        this.dispatch(PRESENCE_NOTIFY_CHANNEL, payload);
      });
      await client.listen(ENTITY_NOTIFY_CHANNEL, (payload) => {
        this.dispatch(ENTITY_NOTIFY_CHANNEL, payload);
      });
      this.started = true;
    } catch (error) {
      this.started = false;
      throw error;
    }
  }
}

let hub: PresenceNotifyHub | null = null;

export function getPresenceNotifyHub(): PresenceNotifyHub {
  hub ??= new PresenceNotifyHub(() => createListenClient());
  return hub;
}
