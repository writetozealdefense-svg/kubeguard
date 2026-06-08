/**
 * Auth context (D3). Two login modes:
 *   - local-admin (air-gapped): a bearer token, no external IdP. Always available.
 *   - OIDC/SSO: redirect to the configured authorize URL; the callback stores the
 *     returned JWT. DEFAULT OFF — only enabled when VITE_OIDC_AUTHORIZE_URL is set.
 *
 * The session token is carried to the API on every call. The API is the single
 * trust boundary: the UI only hides/disables what a role can't do — it never
 * relies on that for security (the server re-checks every request).
 */
import { createContext, useContext, useMemo, useState, type ReactNode } from "react";

export type Role = "viewer" | "analyst" | "admin";

export interface Session {
  user: string;
  role: Role;
  token: string | null;
  tenant: string;
}

interface AuthState {
  session: Session | null;
  loginLocalAdmin: (token: string) => void;
  loginWithToken: (token: string) => void;
  beginSSO: () => void;
  ssoEnabled: boolean;
  logout: () => void;
  can: (action: "trigger_scan" | "manage") => boolean;
}

const AuthContext = createContext<AuthState | null>(null);
const STORAGE_KEY = "kg.session";
const ROLE_RANK: Record<Role, number> = { viewer: 1, analyst: 2, admin: 3 };

function ssoAuthorizeUrl(): string | undefined {
  return import.meta.env.VITE_OIDC_AUTHORIZE_URL || undefined;
}

/** Decode a JWT payload (display only — never trusted for authz). */
export function decodeToken(token: string): { tenant: string; role: Role; sub: string } | null {
  try {
    const part = token.split(".")[1];
    if (!part) return null;
    const json = JSON.parse(atob(part.replace(/-/g, "+").replace(/_/g, "/")));
    const role = (["viewer", "analyst", "admin"] as const).includes(json.role) ? json.role : "viewer";
    return { tenant: json.tenant ?? "default", role, sub: json.sub ?? "user" };
  } catch {
    return null;
  }
}

export function loadSession(): Session | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? (JSON.parse(raw) as Session) : null;
  } catch {
    return null;
  }
}

function persist(s: Session | null) {
  try {
    if (s) localStorage.setItem(STORAGE_KEY, JSON.stringify(s));
    else localStorage.removeItem(STORAGE_KEY);
  } catch {
    /* storage unavailable (e.g. SSR/tests) — in-memory only */
  }
}

export function AuthProvider({ children, initial }: { children: ReactNode; initial?: Session | null }) {
  const [session, setSession] = useState<Session | null>(initial ?? loadSession());

  const value = useMemo<AuthState>(() => {
    const set = (s: Session | null) => {
      persist(s);
      setSession(s);
    };
    return {
      session,
      loginLocalAdmin: (token: string) =>
        set({ user: "local-admin", role: "admin", tenant: "default", token }),
      loginWithToken: (token: string) => {
        const claims = decodeToken(token);
        set({
          user: claims?.sub ?? "user",
          role: claims?.role ?? "viewer",
          tenant: claims?.tenant ?? "default",
          token,
        });
      },
      beginSSO: () => {
        const url = ssoAuthorizeUrl();
        if (url) window.location.assign(url);
      },
      ssoEnabled: Boolean(ssoAuthorizeUrl()),
      logout: () => set(null),
      can: (action) => {
        if (!session) return false;
        if (action === "manage") return session.role === "admin";
        if (action === "trigger_scan") return ROLE_RANK[session.role] >= ROLE_RANK.analyst;
        return false;
      },
    };
  }, [session]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
