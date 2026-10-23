import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { test } from "node:test";
import { Client } from "pg";
import { migrateDown, migrateUp } from "../src/db/migrations.js";

const testDatabaseUrl = process.env.TEST_DATABASE_URL;

test("users migration applies constraints and rolls back cleanly", {
  skip: !testDatabaseUrl,
}, async () => {
  const client = new Client({ connectionString: testDatabaseUrl });
  const schema = `migration_test_${randomUUID().replaceAll("-", "")}`;

  await client.connect();
  try {
    await client.query(`CREATE SCHEMA "${schema}"`);
    await client.query(`SET search_path TO "${schema}"`);

    await migrateUp(client);
    const inserted = await client.query<{ is_active: boolean }>(
      `INSERT INTO users (email, phone_number)
       VALUES ('person@example.com', '+15555550123')
       RETURNING is_active`,
    );
    assert.equal(inserted.rows[0]?.is_active, true);

    await assert.rejects(
      client.query("INSERT INTO users (email, phone_number) VALUES ($1, $2)", [
        "person@example.com",
        "+15555550124",
      ]),
      { code: "23505" },
    );
    await assert.rejects(
      client.query("INSERT INTO users (email, phone_number) VALUES ($1, $2)", [
        "other@example.com",
        "+15555550123",
      ]),
      { code: "23505" },
    );
    await assert.rejects(
      client.query("INSERT INTO users (email, phone_number) VALUES ($1, $2)", [
        "other@example.com",
        "not-e164",
      ]),
      { code: "23514" },
    );

    await migrateDown(client);
    const table = await client.query(
      "SELECT to_regclass('users') AS users_table",
    );
    assert.equal(table.rows[0]?.users_table, null);

    await migrateUp(client);
    const columns = await client.query<{ column_name: string; is_nullable: string }>(
      `SELECT column_name, is_nullable
       FROM information_schema.columns
       WHERE table_schema = $1 AND table_name = 'users'`,
      [schema],
    );
    assert.ok(columns.rows.some((column) => column.column_name === "email" && column.is_nullable === "NO"));
    assert.ok(columns.rows.some((column) => column.column_name === "phone_number" && column.is_nullable === "NO"));
  } finally {
    await client.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`);
    await client.end();
  }
});
