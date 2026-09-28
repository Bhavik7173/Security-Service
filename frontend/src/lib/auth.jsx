import { createContext, useCallback, useContext, useEffect, useState } from "react";
import { api, getToken, setToken } from "./api";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [ready, setReady] = useState(() => !getToken());

  const logout = useCallback(() => {
    setToken(null);
    setUser(null);
  }, []);

  const refresh = useCallback(async () => {
    try {
      setUser(await api("/api/auth/me"));
    } catch {
      logout();
    } finally {
      setReady(true);
    }
  }, [logout]);

  useEffect(() => {
    if (getToken()) refresh();
    const onExpired = () => logout();
    window.addEventListener("auth:expired", onExpired);
    return () => window.removeEventListener("auth:expired", onExpired);
  }, [refresh, logout]);

  const login = async (username, password) => {
    const res = await api("/api/auth/login", { method: "POST", body: { username, password } });
    setToken(res.token);
    setUser(res.user);
    return res.user;
  };

  return (
    <AuthContext.Provider value={{ user, ready, login, logout, refresh, isAdmin: user?.role === "admin" }}>
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => useContext(AuthContext);
