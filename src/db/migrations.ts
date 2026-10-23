import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { Client } from "pg";

const migrations = ["001_create_users"];
const migrationsDirectory = join(dirname(fileURLToPath(import.meta.url)), "migrations");

export async function migrateUp(client: Client): Promise<void> {
  await client.query(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      name text PRIMARY KEY,
      applied_at timestamptz NOT NULL DEFAULT now()
    )
  `);

  for (const name of migrations) {
    const applied = await client.query<{ name: string }>(
      "SELECT name FROM schema_migrations WHERE name = $1",
      [name],
    );
    if (applied.rowCount) continue;

    const sql = await readFile(join(migrationsDirectory, `${name}.up.sql`), "utf8");
    await client.query("BEGIN");
    try {
      await client.query(sql);
      await client.query("INSERT INTO schema_migrations (name) VALUES ($1)", [name]);
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    }
  }
}

export async function migrateDown(client: Client): Promise<void> {
  await client.query(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      name text PRIMARY KEY,
      applied_at timestamptz NOT NULL DEFAULT now()
    )
  `);
  const applied = await client.query<{ name: string }>(
    "SELECT name FROM schema_migrations ORDER BY applied_at DESC LIMIT 1",
  );
  const name = applied.rows[0]?.name;
  if (!name) return;
  if (!migrations.includes(name)) {
    throw new Error(`No rollback migration is registered for ${name}`);
  }

  const sql = await readFile(join(migrationsDirectory, `${name}.down.sql`), "utf8");
  await client.query("BEGIN");
  try {
    await client.query(sql);
    await client.query("DELETE FROM schema_migrations WHERE name = $1", [name]);
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  }
}
