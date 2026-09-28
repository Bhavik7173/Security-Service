import { StrictMode, lazy } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { Loader2 } from "lucide-react";
import "./styles.css";
import { AuthProvider, useAuth } from "./lib/auth";
import { ToastProvider } from "./lib/toast";
import Layout from "./components/Layout";
import Login from "./pages/Login";
import Frozen from "./pages/Frozen";

// Pages load on demand so the charting library only ships with the pages that use it.
const Dashboard = lazy(() => import("./pages/Dashboard"));
const Messages = lazy(() => import("./pages/Messages"));
const Files = lazy(() => import("./pages/Files"));
const Security = lazy(() => import("./pages/Security"));
const Logs = lazy(() => import("./pages/Logs"));
const Network = lazy(() => import("./pages/Network"));
const Admin = lazy(() => import("./pages/Admin"));
const Profile = lazy(() => import("./pages/Profile"));

const Spinner = () => (
  <div style={{ display: "grid", placeItems: "center", height: "100%", minHeight: 240 }} aria-busy="true">
    <Loader2 className="spin" size={28} aria-label="Loading" />
  </div>
);

function App() {
  const { user, ready, isAdmin } = useAuth();
  if (!ready) {
    return <Spinner />;
  }
  if (!user) return <Login />;
  if (user.status === "frozen") return <Frozen />;

  return (
    <Routes>
      <Route element={<Layout fallback={<Spinner />} />}>
        <Route index element={<Dashboard />} />
        <Route path="messages" element={<Messages />} />
        <Route path="files" element={<Files />} />
        <Route path="security" element={<Security />} />
        <Route path="logs" element={<Logs />} />
        <Route path="profile" element={<Profile />} />
        {isAdmin && <Route path="network" element={<Network />} />}
        {isAdmin && <Route path="admin" element={<Admin />} />}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}

createRoot(document.getElementById("root")).render(
  <StrictMode>
    <BrowserRouter>
      <ToastProvider>
        <AuthProvider>
          <App />
        </AuthProvider>
      </ToastProvider>
    </BrowserRouter>
  </StrictMode>
);
