ALTER TABLE "oauth_client_assertion" ADD COLUMN "id" text PRIMARY KEY DEFAULT gen_random_uuid()::text NOT NULL;--> statement-breakpoint
ALTER TABLE "oauth_client_resource" ADD COLUMN "id" text PRIMARY KEY DEFAULT gen_random_uuid()::text NOT NULL;--> statement-breakpoint
ALTER TABLE "oauth_resource" ADD COLUMN "id" text PRIMARY KEY DEFAULT gen_random_uuid()::text NOT NULL;--> statement-breakpoint
ALTER TABLE "oauth_client_assertion" ALTER COLUMN "id" DROP DEFAULT;--> statement-breakpoint
ALTER TABLE "oauth_client_resource" ALTER COLUMN "id" DROP DEFAULT;--> statement-breakpoint
ALTER TABLE "oauth_resource" ALTER COLUMN "id" DROP DEFAULT;
