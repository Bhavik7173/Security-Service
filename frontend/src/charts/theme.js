import { useEffect, useState } from "react";

const VARS = ["--series-1", "--series-2", "--status-warning", "--status-critical", "--surface", "--grid", "--axis", "--text-3"];

function read() {
  const cs = getComputedStyle(document.documentElement);
  return Object.fromEntries(VARS.map((v) => [v.slice(2), cs.getPropertyValue(v).trim()]));
}

/** Chart colours resolved from CSS tokens; updates when the theme toggles or the OS scheme changes. */
export function useChartTheme() {
  const [colors, setColors] = useState(read);
  useEffect(() => {
    const update = () => setColors(read());
    const observer = new MutationObserver(update);
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    mq.addEventListener("change", update);
    return () => { observer.disconnect(); mq.removeEventListener("change", update); };
  }, []);
  return colors;
}
