import { ITEMS } from '../../../lib';
export const GET = async (req, { params }) => {
  const { id } = await params;
  const it = ITEMS.find(i => String(i.id) === id);
  return it ? Response.json(it) : Response.json({ error: 'not found' }, { status: 404 });
};
