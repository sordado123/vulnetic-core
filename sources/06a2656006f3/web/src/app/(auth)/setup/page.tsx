"use client";

import { useEffect, useState } from "react";

import { useRouter } from "next/navigation";

import { AuthShell } from "@/components/auth-shell";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api } from "@/lib/api";
import { auth } from "@/lib/auth";

export default function SetupPage() {
  const router = useRouter();
  const [accountName, setAccountName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [checking, setChecking] = useState(true);
  const [publicSignup,setPublicSignup]=useState(false);
  // Multi-tenant: signup stays open forever (a second, third, ... customer still
  // needs this page), so there is nothing to redirect away from here. The only
  // thing worth checking up front is whether the backend can be reached at all.
  const [unavailable, setUnavailable] = useState(false);

  useEffect(() => {
    api
      .authStatus()
      .then(status=>setPublicSignup(status.public_signup===true))
      .catch((err) => {
        setError(err instanceof Error ? err.message : "Unable to connect to the backend service");
        setUnavailable(true);
      })
      .finally(() => setChecking(false));
  }, []);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (password !== confirm) {
      setError("The two passwords do not match");
      return;
    }
    if (password.length < 8) {
      setError("Password must be at least 8 characters");
      return;
    }
    setLoading(true);
    setError("");
    try {
      const { token } = await api.signup(accountName, email, password);
      await auth.setToken(token);
      router.replace("/function/tasks");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Signup failed");
    } finally {
      setLoading(false);
    }
  }

  if (checking) return null;

  return (
    <>
      <AuthShell>
        <div className="space-y-8">
          <div className="space-y-3">
            <h1 className="text-[28px] font-semibold tracking-tight">{unavailable ? "Cannot reach the backend" : publicSignup ? "Create your free account" : "Create your account"}</h1>
            <p className="text-sm leading-relaxed text-muted-foreground">
              {unavailable
                ? "The backend or database is temporarily unavailable — restore the service and try again."
                : publicSignup ? "Free access. Bring your own LLM API key and Linux or Windows executor." : "Set up your organization's invited Vulnetic account"}
            </p>
          </div>
          {unavailable ? (
            <div className="flex flex-col gap-5">
              {error && <p className="text-center text-sm text-destructive">{error}</p>}
              <Button type="button" className="w-full" onClick={() => window.location.reload()}>
                Retry
              </Button>
            </div>
          ) : (
            <form onSubmit={handleSubmit} className="flex flex-col gap-5">
              <div className="space-y-1.5">
                <Label htmlFor="account-name">Organization name</Label>
                <Input
                  id="account-name"
                required
                className="h-11"
                  value={accountName}
                  onChange={(e) => setAccountName(e.target.value)}
                  placeholder="Acme Security"
                  autoFocus
                  autoComplete="organization"
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="email">Email</Label>
                <Input
                  id="email"
                required
                className="h-11"
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="you@company.com"
                  autoComplete="email"
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="password">Password</Label>
                <Input
                  id="password"
                required
                className="h-11"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="At least 8 characters"
                  autoComplete="new-password"
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="confirm">Confirm password</Label>
                <Input
                  id="confirm"
                required
                className="h-11"
                  type="password"
                  value={confirm}
                  onChange={(e) => setConfirm(e.target.value)}
                  placeholder="Enter the password again"
                  autoComplete="new-password"
                />
              </div>
              {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
              <Button type="submit" className="h-11 w-full" disabled={loading || !accountName || !email || !password || !confirm}>
                {loading ? "Creating account..." : "Create account and sign in"}
              </Button>
              <p className="text-center text-sm text-muted-foreground">
                Already have an account?{" "}
                <a href="/login" className="font-medium text-primary underline-offset-4 hover:underline">
                  Sign in
                </a>
              </p>
            </form>
          )}
        </div>
      </AuthShell>
    </>
  );
}
