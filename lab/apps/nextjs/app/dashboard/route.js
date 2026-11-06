import { userOf } from '../lib';
export const dynamic = 'force-dynamic';
export const GET = req => {
  const u = userOf(req);
  return u ? new Response(`<h1>Welcome ${u}</h1>`, { headers: { 'content-type': 'text/html' } })
           : new Response(null, { status: 302, headers: { location: '/login' } });
};
