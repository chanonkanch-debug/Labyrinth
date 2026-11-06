'use client';
import { useEffect, useState } from 'react';
// A real client-rendered page: loading it pulls several /_next/static chunks, which is the
// "browser page-load burst" the lab uses to check Labyrinth doesn't flag normal browsers.
export default function Home() {
  const [items, setItems] = useState([]);
  useEffect(() => { fetch('/api/items').then(r => r.json()).then(setItems); }, []);
  return <main><h1>Lab shop</h1><ul>{items.map(i => <li key={i.id}>{i.name}</li>)}</ul><a href="/login">Sign in</a></main>;
}
