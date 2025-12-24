import { Pool, QueryResult, QueryResultRow } from 'pg';

const globalForPg = globalThis as unknown as {
  pgPool?: Pool;
};

// Shared PG pool to avoid opening a new connection per request
export const pgPool =
  globalForPg.pgPool ??
  new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
      rejectUnauthorized: false,
    },
    max: 10,
  });

if (process.env.NODE_ENV !== 'production') {
  globalForPg.pgPool = pgPool;
}

type SqlParam = string | number | boolean | Date | Uint8Array | null;

export async function dbQuery<T extends QueryResultRow = QueryResultRow>(
  text: string,
  params?: ReadonlyArray<SqlParam>
): Promise<QueryResult<T>> {
  const client = await pgPool.connect();
  try {
    return await client.query<T>(text, params ? [...params] : undefined);
  } finally {
    client.release();
  }
}

