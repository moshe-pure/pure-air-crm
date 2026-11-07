// Pure Air CRM – data API. Every request must carry a valid Microsoft sign-in token of the pure-air-projects tenant.
import { neon } from '@neondatabase/serverless';
import { createRemoteJWKSet, jwtVerify } from 'jose';

const TENANT = '2057ccaf-d08f-4cd9-9f95-6bc40ff75a01';
const CLIENT = '02482120-67bf-4043-adf5-39d8bb8bacb7';
const KINDS = ['clients', 'contacts', 'units', 'activities', 'quotes', 'leads', 'tasks', 'instruments', 'jobs'];
const JWKS = createRemoteJWKSet(new URL(`https://login.microsoftonline.com/${TENANT}/discovery/v2.0/keys`));
const sql = neon(process.env.DATABASE_URL);
let ready = false;

async function init() {
  if (ready) return;
  await sql`create table if not exists items (id bigserial primary key, kind text not null, data jsonb not null default '{}'::jsonb, created_at timestamptz not null default now(), updated_at timestamptz not null default now(), updated_by text)`;
  await sql`create index if not exists items_kind_idx on items(kind)`;
  ready = true;
}

async function auth(req) {
  const token = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  if (!token) throw new Error('no token');
  const { payload } = await jwtVerify(token, JWKS, { issuer: `https://login.microsoftonline.com/${TENANT}/v2.0`, audience: CLIENT });
  if (payload.tid !== TENANT) throw new Error('wrong tenant');
  return payload.preferred_username || payload.name || 'unknown';
}

const row = r => ({ ...r.data, id: String(r.id) });

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  let user;
  try { user = await auth(req); } catch { return res.status(401).json({ error: 'unauthorized' }); }
  try {
    await init();
    const id = req.query.id ? Number(req.query.id) : null;
    if (req.method === 'GET') {
      const rows = await sql`select id, kind, data from items order by id`;
      const out = Object.fromEntries(KINDS.map(k => [k, []]));
      for (const r of rows) if (out[r.kind]) out[r.kind].push(row(r));
      return res.status(200).json(out);
    }
    if (req.method === 'POST') {
      const { kind, fields } = req.body || {};
      if (!KINDS.includes(kind)) return res.status(400).json({ error: 'bad kind' });
      const [r] = await sql`insert into items (kind, data, updated_by) values (${kind}, ${JSON.stringify(fields || {})}::jsonb, ${user}) returning id, kind, data`;
      return res.status(200).json(row(r));
    }
    if (req.method === 'PATCH' && id) {
      const { fields } = req.body || {};
      await sql`update items set data = data || ${JSON.stringify(fields || {})}::jsonb, updated_at = now(), updated_by = ${user} where id = ${id}`;
      return res.status(200).json({ ok: true });
    }
    if (req.method === 'DELETE' && id) {
      await sql`delete from items where id = ${id}`;
      return res.status(200).json({ ok: true });
    }
    return res.status(405).json({ error: 'method' });
  } catch (e) {
    return res.status(500).json({ error: String(e.message || e) });
  }
}
