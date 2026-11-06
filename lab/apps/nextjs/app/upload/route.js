export const POST = async req => {
  const f = (await req.formData()).get('file');
  return Response.json({ size: f ? f.size : 0 });
};
