import "dotenv/config";
import { Client } from "pg";
import { loadConfig } from "../config/env.js";
import { migrateDown, migrateUp } from "./migrations.js";

const direction = process.argv[2];
if (direction !== "up" && direction !== "down") {
  throw new Error("Specify migration direction as 'up' or 'down'");
}

const config = loadConfig();
const client = new Client({ connectionString: config.DATABASE_URL });

try {
  await client.connect();
  if (direction === "up") {
    await migrateUp(client);
  } else {
    await migrateDown(client);
  }
  console.log(`Database migration ${direction} completed`);
} finally {
  await client.end();
}
