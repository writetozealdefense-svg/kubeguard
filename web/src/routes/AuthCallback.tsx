/**
 * OIDC redirect callback (D3 seam). The IdP redirects here with the token in the
 * URL fragment (#token=... or #access_token=...). We store it and land on the
 * overview. Default off — only reached when SSO is configured. The token is
 * verified server-side on every API call (the API is the trust boundary).
 */
import { useEffect, useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { useAuth } from "@/app/auth";

function tokenFromFragment(): string | null {
  const frag = window.location.hash.startsWith("#") ? window.location.hash.slice(1) : window.location.hash;
  const params = new URLSearchParams(frag);
  return params.get("token") ?? params.get("access_token");
}

export function AuthCallback() {
  const { loginWithToken } = useAuth();
  const navigate = useNavigate();
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const token = tokenFromFragment();
    if (!token) {
      setError("No token in callback.");
      return;
    }
    loginWithToken(token);
    void navigate({ to: "/" });
  }, [loginWithToken, navigate]);

  return <p className="p-6 text-fg-muted">{error ?? "Completing sign-in…"}</p>;
}
