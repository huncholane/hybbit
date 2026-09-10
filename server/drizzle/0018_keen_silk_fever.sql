ALTER TABLE "sites" ADD COLUMN "track_heartbeat" boolean DEFAULT false;--> statement-breakpoint
ALTER TABLE "sites" ADD COLUMN "heartbeat_interval" integer DEFAULT 15;