export const dynamic = 'force-dynamic';
export const GET = () => {
  const enc = new TextEncoder();
  const stream = new ReadableStream({
    async start(c) {
      for (let n = 1; n <= 3; n++) { c.enqueue(enc.encode(`data: tick ${n}\n\n`)); await new Promise(r => setTimeout(r, 500)); }
      c.close();
    },
  });
  return new Response(stream, { headers: { 'content-type': 'text/event-stream', 'cache-control': 'no-cache' } });
};
