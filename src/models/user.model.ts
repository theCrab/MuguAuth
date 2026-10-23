import type { Pool } from "pg";
import { ApiError } from "../services/api.error.js";
import type { RegistrationContacts } from "../services/registration.store.js";

export interface User {
  id: string;
  email: string;
  phone_number: string;
  is_active: boolean;
  created_at: Date;
}

export interface UserRepository {
  createOrGetByContacts(contacts: RegistrationContacts): Promise<User>;
}

export interface UserStatusRepository {
  findById(id: string): Promise<User | null>;
}

export class ContactAlreadyRegisteredError extends ApiError {
  constructor() {
    super(409, "CONTACT_ALREADY_REGISTERED", "Email or phone number is already registered");
    this.name = "ContactAlreadyRegisteredError";
  }
}

export class UserModel implements UserRepository, UserStatusRepository {
  constructor(private readonly pool: Pool) {}

  async createOrGetByContacts(contacts: RegistrationContacts): Promise<User> {
    const inserted = await this.pool.query<User>(
      `INSERT INTO users (email, phone_number)
       VALUES ($1, $2)
       ON CONFLICT DO NOTHING
       RETURNING id, email, phone_number, is_active, created_at`,
      [contacts.email, contacts.phoneNumber],
    );
    if (inserted.rows[0]) return inserted.rows[0];

    const existing = await this.pool.query<User>(
      `SELECT id, email, phone_number, is_active, created_at
       FROM users
       WHERE email = $1 OR phone_number = $2`,
      [contacts.email, contacts.phoneNumber],
    );
    const sameAccount = existing.rows.find(
      (user) => user.email === contacts.email && user.phone_number === contacts.phoneNumber,
    );
    if (sameAccount) return sameAccount;

    throw new ContactAlreadyRegisteredError();
  }

  async findById(id: string): Promise<User | null> {
    const result = await this.pool.query<User>(
      `SELECT id, email, phone_number, is_active, created_at
       FROM users
       WHERE id = $1`,
      [id],
    );
    return result.rows[0] ?? null;
  }
}
