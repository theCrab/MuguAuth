import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { test } from "node:test";
import { Client, Pool } from "pg";
import { migrateUp } from "../src/db/migrations.js";
import {
  ContactAlreadyRegisteredError,
  UserModel,
} from "../src/models/user.model.js";

const testDatabaseUrl = process.env.TEST_DATABASE_URL;

test("user creation is idempotent and enforces unique contact methods", {
  skip: !testDatabaseUrl,
}, async () => {
  if (!testDatabaseUrl) throw new Error("TEST_DATABASE_URL must be set for database tests");
  const schema = `user_test_${randomUUID().replaceAll("-", "")}`;
  const setupClient = new Client({ connectionString: testDatabaseUrl });
  let pool: Pool | undefined;

  await setupClient.connect();
  try {
    await setupClient.query(`CREATE SCHEMA "${schema}"`);
    await setupClient.query(`SET search_path TO "${schema}"`);
    await migrateUp(setupClient);

    pool = new Pool({
      connectionString: testDatabaseUrl,
      options: `-c search_path=${schema}`,
    });
    const users = new UserModel(pool);
    const contacts = { email: "person@example.com", phoneNumber: "+14155552671" };
    const concurrentResults = await Promise.all(
      Array.from({ length: 8 }, () => users.createOrGetByContacts(contacts)),
    );
    assert.equal(new Set(concurrentResults.map((user) => user.id)).size, 1);
    assert.equal(concurrentResults[0]?.is_active, true);

    await assert.rejects(
      users.createOrGetByContacts({
        email: "other@example.com",
        phoneNumber: contacts.phoneNumber,
      }),
      ContactAlreadyRegisteredError,
    );
    await assert.rejects(
      users.createOrGetByContacts({
        email: contacts.email,
        phoneNumber: "+14155552672",
      }),
      ContactAlreadyRegisteredError,
    );

    const count = await pool.query<{ count: string }>("SELECT count(*) FROM users");
    assert.equal(count.rows[0]?.count, "1");
  } finally {
    await pool?.end();
    await setupClient.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`);
    await setupClient.end();
  }
});
