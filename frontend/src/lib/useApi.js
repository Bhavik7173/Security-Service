import { useCallback, useEffect, useState } from "react";
import { api } from "./api";

/** Load JSON from an endpoint; returns { data, error, loading, reload }. */
export function useApi(path) {
  const [state, setState] = useState({ data: null, error: null, loading: true });

  const load = useCallback(async () => {
    if (!path) return;
    setState((s) => ({ ...s, loading: true, error: null }));
    try {
      const data = await api(path);
      setState({ data, error: null, loading: false });
    } catch (error) {
      setState((s) => ({ ...s, error, loading: false }));
    }
  }, [path]);

  useEffect(() => {
    load();
  }, [load]);

  return { ...state, reload: load };
}

export const fmtDate = (d) =>
  new Date(d.replace(" ", "T")).toLocaleDateString(undefined, { month: "short", day: "numeric" });

export const fmtDateTime = (d) =>
  d ? new Date(d.replace(" ", "T")).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }) : "—";

export const fmtBytes = (b) => {
  if (!b) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const i = Math.min(Math.floor(Math.log(b) / Math.log(1024)), units.length - 1);
  return `${(b / 1024 ** i).toFixed(i ? 1 : 0)} ${units[i]}`;
};
