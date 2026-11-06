export const ITEMS = [{ id: 1, name: 'Widget' }, { id: 2, name: 'Gadget' }];
// In-memory sessions: fine for a single lab process.
globalThis.__sessions ??= new Map();
export const sessions = globalThis.__sessions;
export const userOf = req => sessions.get(req.cookies.get('sid')?.value);
