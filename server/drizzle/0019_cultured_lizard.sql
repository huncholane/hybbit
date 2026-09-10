ALTER TABLE "organization" ADD COLUMN "excluded_ips" jsonb DEFAULT '[]'::jsonb;--> statement-breakpoint
ALTER TABLE "sites" ADD COLUMN "use_organization_excluded_ips" boolean DEFAULT true;