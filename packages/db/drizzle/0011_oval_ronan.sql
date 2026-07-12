ALTER TABLE "devices" ADD COLUMN "name" text DEFAULT '' NOT NULL;--> statement-breakpoint
UPDATE "devices"
SET "name" = COALESCE(
  NULLIF(TRIM(metadata->>'hostname'), ''),
  LEFT(endpoint_id, 8)
)
WHERE "name" = '';
