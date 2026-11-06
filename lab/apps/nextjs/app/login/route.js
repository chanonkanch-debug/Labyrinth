import { randomBytes } from 'crypto';
import { NextResponse } from 'next/server';
import { sessions } from '../lib';
export const GET = () => new Response('<form method="post" action="/login"><input name="username"><input name="password" type="password"><button>Sign in</button></form>', { headers: { 'content-type': 'text/html' } });
export const POST = async req => {
  const f = await req.formData();
  if (f.get('username') === 'alice' && f.get('password') === 'wonderland') {
    const sid = randomBytes(16).toString('hex');
    sessions.set(sid, 'alice');
    const r = new NextResponse(null, { status: 302, headers: { location: '/dashboard' } });
    r.cookies.set('sid', sid, { httpOnly: true, sameSite: 'lax' });
    r.cookies.set('theme', 'dark');
    return r;
  }
  return new Response('invalid credentials', { status: 401 });
};
