import { userOf } from '../lib';
export const POST = req => userOf(req) ? Response.json({ ok: true, order: 1001 }) : Response.json({ error: 'login required' }, { status: 401 });
