'use server';

import * as bcrypt from 'bcryptjs';
import { DbUser, findUserByIdentifier, updateLastLogin } from '@/lib/data/users';

export interface AuthPayload {
  id: string;
  username: string;
  email: string;
  role: string;
  exp: number;
  iat: number;
}

export type AuthResult =
  | { status: 'ok'; user: DbUser; payload: AuthPayload; token: string }
  | { status: 'not_found' }
  | { status: 'inactive' }
  | { status: 'invalid_password' }
  | { status: 'error'; message: string };

function encodeBase64(input: string) {
  return Buffer.from(input, 'utf8').toString('base64');
}

function buildUnsignedToken(payload: AuthPayload) {
  const header = encodeBase64(JSON.stringify({ alg: 'none', typ: 'JWT' }));
  const body = encodeBase64(JSON.stringify(payload));
  return `${header}.${body}.signature`;
}

export async function authenticateUser(
  identifier: string,
  password: string
): Promise<AuthResult> {
  const user = await findUserByIdentifier(identifier);
  if (!user) return { status: 'not_found' };
  if (!user.is_active) return { status: 'inactive' };

  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) return { status: 'invalid_password' };

  await updateLastLogin(user.id);

  const now = Math.floor(Date.now() / 1000);
  const payload: AuthPayload = {
    id: user.id.toString(),
    username: user.username,
    email: user.email,
    role: user.role,
    exp: now + 24 * 60 * 60,
    iat: now,
  };

  return {
    status: 'ok',
    user,
    payload,
    token: buildUnsignedToken(payload),
  };
}

