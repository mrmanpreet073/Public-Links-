CREATE TABLE "oauth_clients" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"app_name" varchar(255) NOT NULL,
	"client_id" varchar(255) NOT NULL,
	"client_secret" varchar(255) NOT NULL,
	"redirect_uri" text NOT NULL,
	"scope" text,
	"response_type" varchar(50) DEFAULT 'code',
	"created_at" timestamp DEFAULT now()
);
