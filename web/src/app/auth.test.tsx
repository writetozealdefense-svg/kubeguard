import { act, renderHook } from "@testing-library/react";
import { beforeEach, describe, expect, it } from "vitest";
import { AuthProvider, decodeToken, loadSession, useAuth } from "./auth";
import type { ReactNode } from "react";

function jwt(payload: Record<string, unknown>): string {
  const b64 = (o: unknown) => btoa(JSON.stringify(o)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return `${b64({ alg: "RS256" })}.${b64(payload)}.sig`;
}

const wrapper = ({ children }: { children: ReactNode }) => <AuthProvider>{children}</AuthProvider>;

beforeEach(() => localStorage.clear());

describe("decodeToken", () => {
  it("extracts tenant, role, sub from a JWT payload", () => {
    const claims = decodeToken(jwt({ sub: "u9", tenant: "acme", role: "analyst" }));
    expect(claims).toEqual({ sub: "u9", tenant: "acme", role: "analyst" });
  });
  it("defaults an unknown role to viewer (least privilege)", () => {
    expect(decodeToken(jwt({ sub: "u", tenant: "t", role: "superuser" }))?.role).toBe("viewer");
  });
  it("returns null on a malformed token", () => {
    expect(decodeToken("not-a-jwt")).toBeNull();
  });
});

describe("auth login modes + role gating", () => {
  it("local-admin login yields an admin session, persisted, that can do everything", () => {
    const { result } = renderHook(() => useAuth(), { wrapper });
    act(() => result.current.loginLocalAdmin("local-admin"));
    expect(result.current.session?.role).toBe("admin");
    expect(result.current.can("trigger_scan")).toBe(true);
    expect(result.current.can("manage")).toBe(true);
    // persisted across reloads
    expect(loadSession()?.token).toBe("local-admin");
  });

  it("a viewer JWT cannot trigger scans or manage", () => {
    const { result } = renderHook(() => useAuth(), { wrapper });
    act(() => result.current.loginWithToken(jwt({ sub: "v", tenant: "acme", role: "viewer" })));
    expect(result.current.session?.role).toBe("viewer");
    expect(result.current.can("trigger_scan")).toBe(false);
    expect(result.current.can("manage")).toBe(false);
  });

  it("an analyst JWT can trigger scans but not manage", () => {
    const { result } = renderHook(() => useAuth(), { wrapper });
    act(() => result.current.loginWithToken(jwt({ sub: "a", tenant: "acme", role: "analyst" })));
    expect(result.current.can("trigger_scan")).toBe(true);
    expect(result.current.can("manage")).toBe(false);
  });

  it("logout clears the persisted session", () => {
    const { result } = renderHook(() => useAuth(), { wrapper });
    act(() => result.current.loginLocalAdmin("local-admin"));
    act(() => result.current.logout());
    expect(result.current.session).toBeNull();
    expect(loadSession()).toBeNull();
  });

  it("SSO is disabled unless an authorize URL is configured", () => {
    const { result } = renderHook(() => useAuth(), { wrapper });
    expect(result.current.ssoEnabled).toBe(false);
  });
});
