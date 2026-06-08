/**
 * Login (D3). Local-admin works with zero external dependencies (air-gapped).
 * "Sign in with SSO" is shown only when OIDC is configured
 * (VITE_OIDC_AUTHORIZE_URL) — the ready-to-connect seam, default off.
 */
import { useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { useAuth } from "@/app/auth";
import { Button, Card, CardTitle } from "@/components/ui/primitives";

export function Login() {
  const { loginLocalAdmin, beginSSO, ssoEnabled } = useAuth();
  const navigate = useNavigate();
  const [token, setToken] = useState("local-admin");

  return (
    <div className="mx-auto mt-24 max-w-sm">
      <Card className="space-y-4">
        <CardTitle>Sign in to KubeGuard</CardTitle>

        {ssoEnabled && (
          <Button className="w-full" onClick={beginSSO} aria-label="Sign in with SSO">
            Sign in with SSO
          </Button>
        )}

        <form
          className="space-y-2"
          onSubmit={(e) => {
            e.preventDefault();
            loginLocalAdmin(token);
            void navigate({ to: "/" });
          }}
        >
          <label className="block text-xs text-fg-subtle" htmlFor="admin-token">
            Local-admin token (air-gapped)
          </label>
          <input
            id="admin-token"
            className="w-full rounded-md border border-border bg-bg-raised px-2 py-1.5 text-sm text-fg"
            value={token}
            onChange={(e) => setToken(e.target.value)}
          />
          <Button type="submit" variant="ghost" className="w-full">
            Continue as local admin
          </Button>
        </form>
      </Card>
    </div>
  );
}
