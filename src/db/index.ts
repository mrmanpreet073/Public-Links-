// import 'dotenv/config';
// import { drizzle } from 'drizzle-orm/node-postgres';

//  export const db = drizzle(process.env.DATABASE_URL!);


import { drizzle } from "drizzle-orm/node-postgres";
import { Pool } from "pg";

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false // ✅ required for Neon
  }
});

export const db = drizzle(pool);