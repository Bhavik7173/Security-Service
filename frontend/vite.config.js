import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// In development the API runs on :8000 (uvicorn backend.server:app); proxy /api to it.
// `npm run build:demo` produces a self-contained preview that mocks the API in the browser.
export default defineConfig(({ mode }) => ({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: { "/api": "http://127.0.0.1:8000" },
  },
  ...(mode === "demo" && {
    base: "./",
    build: { outDir: "dist-demo", rolldownOptions: { output: { codeSplitting: false } } },
  }),
}));
