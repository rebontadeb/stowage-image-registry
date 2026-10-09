import { useEffect, useState } from "react";

export interface Route { parts: string[]; query: URLSearchParams }

function parse(): Route {
  const h = location.hash.replace(/^#\/?/, "");
  const [path, q = ""] = h.split("?");
  return { parts: path.split("/").filter(Boolean).map(decodeURIComponent), query: new URLSearchParams(q) };
}

export function useRoute(): Route {
  const [r, setR] = useState(parse);
  useEffect(() => {
    const on = () => setR(parse());
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  return r;
}

export const href = (...parts: string[]) => "#/" + parts.map(encodeURIComponent).join("/");
export const go = (...parts: string[]) => { location.hash = href(...parts); };
