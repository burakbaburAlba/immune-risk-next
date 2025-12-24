'use server';

import { dbQuery } from '@/lib/pg';

export interface DbUser {
  id: number;
  username: string;
  email: string;
  role: string;
  password: string;
  is_active: boolean;
  created_at: Date;
  updated_at: Date;
  last_login: Date | null;
}

export async function findUserByIdentifier(
  identifier: string
): Promise<DbUser | null> {
  const result = await dbQuery<DbUser>(
    `
    SELECT id, username, email, role, password, is_active, created_at, updated_at, last_login
    FROM users
    WHERE username = $1 OR email = $1
    LIMIT 1
  `,
    [identifier]
  );

  return result.rows[0] ?? null;
}

export async function createUser(params: {
  username: string;
  email: string;
  password: string;
  role: string;
  isActive?: boolean;
}) {
  const result = await dbQuery<DbUser>(
    `
    INSERT INTO users (username, email, password, role, is_active, created_at, updated_at)
    VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
    RETURNING id, username, email, role, is_active, created_at, updated_at, last_login
  `,
    [
      params.username,
      params.email,
      params.password,
      params.role,
      params.isActive ?? true,
    ]
  );

  const user = result.rows[0];
  return {
    ...user,
    is_active: Boolean(user.is_active),
  };
}

export async function updateLastLogin(userId: number) {
  await dbQuery('UPDATE users SET last_login = NOW() WHERE id = $1', [userId]);
}

