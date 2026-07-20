CREATE TABLE "audit_events" (
	"organization_id" text NOT NULL,
	"sequence_number" bigint NOT NULL,
	"category_uid" smallint NOT NULL,
	"class_uid" smallint NOT NULL,
	"activity_id" smallint NOT NULL,
	"type_uid" integer NOT NULL,
	"severity_id" smallint DEFAULT 1 NOT NULL,
	"status_id" smallint DEFAULT 1 NOT NULL,
	"time" timestamp with time zone DEFAULT now() NOT NULL,
	"message" text NOT NULL,
	"actor_type" text NOT NULL,
	"actor_id" text NOT NULL,
	"actor_name" text,
	"actor_email" text,
	"actor_ip" "inet",
	"actor_ua" text,
	"target_type" text NOT NULL,
	"target_id" text NOT NULL,
	"target_name" text,
	"network_id" uuid,
	"group_id" text,
	"diff_before" jsonb,
	"diff_after" jsonb,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"trace_id" text,
	"prev_entry_hash" text NOT NULL,
	"entry_hash" text NOT NULL,
	"hmac_schema_version" smallint DEFAULT 1 NOT NULL,
	CONSTRAINT "audit_events_pkey" PRIMARY KEY("organization_id","sequence_number","time")
);
--> statement-breakpoint
DROP TABLE "audit_log" CASCADE;--> statement-breakpoint
CREATE INDEX "idx_audit_org_time" ON "audit_events" USING btree ("organization_id","time");--> statement-breakpoint
CREATE INDEX "idx_audit_org_class" ON "audit_events" USING btree ("organization_id","class_uid","time");--> statement-breakpoint
CREATE INDEX "idx_audit_org_actor" ON "audit_events" USING btree ("organization_id","actor_id","time");--> statement-breakpoint
CREATE INDEX "idx_audit_org_target" ON "audit_events" USING btree ("organization_id","target_type","target_id","time");