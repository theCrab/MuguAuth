import { Pool } from "pg";

export function createDatabasePool(connectionString: string): Pool {
  return new Pool({
    connectionString,
    max: 10,
    application_name: "mugu-auth",
  });
}
