export const dynamic = 'force-dynamic';
export const GET = () => new Response(null, { status: 302, headers: { location: '/api/health' } });
