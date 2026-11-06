import { ITEMS } from '../../lib';
export const GET = () => Response.json(ITEMS);
export const POST = async req => Response.json({ id: 3, ...(await req.json()) }, { status: 201 });
