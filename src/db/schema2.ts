import { pgTable, uuid, varchar, text, timestamp } from "drizzle-orm/pg-core";


export const oauthClientsTable = pgTable(
  "oauth_clients",
  {
    id: uuid("id")
      .defaultRandom()
      .primaryKey(),

    appName: varchar("app_name", {
      length: 255
    }).notNull(),

    clientId: varchar("client_id", {
      length: 255
    }).notNull(),


    clientSecret: varchar("client_secret", {
      length: 255
    }).notNull(),

    redirectUri:
      text("redirect_uri").notNull(),

    scope: text("scope"),

    responseType: varchar(
      "response_type",
      {
        length: 50
      }
    ).default("code"),

    createdAt:
      timestamp("created_at")
      .defaultNow()
  }
);