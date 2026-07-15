ALTER TABLE "network_memberships" DROP CONSTRAINT "network_memberships_status_check";--> statement-breakpoint
ALTER TABLE "organization" ADD COLUMN "settings" jsonb DEFAULT '{}'::jsonb NOT NULL;--> statement-breakpoint
ALTER TABLE "devices" ADD COLUMN "labels" jsonb DEFAULT '{}'::jsonb NOT NULL;--> statement-breakpoint
ALTER TABLE "devices" ADD COLUMN "inactivity_ttl" interval;--> statement-breakpoint
ALTER TABLE "devices" ADD COLUMN "expired_at" timestamp with time zone;--> statement-breakpoint
CREATE INDEX "devices_by_expired_at_idx" ON "devices" USING btree ("expired_at");--> statement-breakpoint
ALTER TABLE "network_memberships" ADD CONSTRAINT "network_memberships_status_check" CHECK ("network_memberships"."status" IN ('active', 'suspended', 'pending', 'expired'));