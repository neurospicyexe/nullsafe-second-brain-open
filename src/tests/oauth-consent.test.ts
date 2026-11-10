import { describe, it, expect, afterEach } from "vitest";
import express from "express";
import type { AddressInfo } from "net";
import type { Server } from "http";
import { mcpAuthRouter } from "@modelcontextprotocol/sdk/server/auth/router.js";
import { SingleUserOAuthProvider } from "../oauth-provider.js";
import { createAuthorizeGate, escapeHtml, safeCompare } from "../oauth-consent.js";

const KEY = "the-real-key";
const REDIRECT = "https://client.example/cb";
let server: Server | undefined;

async function boot(clock?: { t: number }) {
  const provider = new SingleUserOAuthProvider(KEY);
  const app = express();
  app.set("trust proxy", 1);
  app.use(express.json());
  app.use(
    "/authorize",
    express.urlencoded({ extended: false, limit: "16kb" }),
    createAuthorizeGate({ passphrase: KEY, now: clock ? () => clock.t : undefined }),
  );
  await new Promise<void>((r) => {
    server = app.listen(0, "127.0.0.1", () => r());
  });
  const base = `http://127.0.0.1:${(server!.address() as AddressInfo).port}`;
  app.use(mcpAuthRouter({ provider, issuerUrl: new URL(base), resourceServerUrl: new URL(base + "/mcp") }));
  const reg = await fetch(base + "/register", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ redirect_uris: [REDIRECT], token_endpoint_auth_method: "none" }),
  });
  const client = (await reg.json()) as { client_id: string };
  const oauth = {
    client_id: client.client_id,
    redirect_uri: REDIRECT,
    response_type: "code",
    code_challenge: "A".repeat(43),
    code_challenge_method: "S256",
    state: 's"<b>&x',
    scope: "",
  };
  const post = (passphrase: string, headers: Record<string, string> = {}) =>
    fetch(base + "/authorize", {
      method: "POST",
      redirect: "manual",
      headers: { "content-type": "application/x-www-form-urlencoded", ...headers },
      body: new URLSearchParams({ ...oauth, passphrase }).toString(),
    });
  return { base, oauth, post };
}

afterEach(async () => {
  await new Promise<void>((r) => (server ? server.close(() => r()) : r()));
  server = undefined;
});

describe("authorize consent gate", () => {
  it("GET renders the form with escaped hidden fields and hardened headers", async () => {
    const { base, oauth } = await boot();
    const res = await fetch(base + "/authorize?" + new URLSearchParams(oauth));
    expect(res.status).toBe(200);
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(res.headers.get("x-frame-options")).toBe("DENY");
    const csp = res.headers.get("content-security-policy")!;
    expect(csp).toContain("default-src 'none'");
    expect(csp).toContain("style-src 'unsafe-inline'");
    expect(csp).toContain("form-action 'self'");
    const html = await res.text();
    expect(html).toContain('name="passphrase"');
    expect(html).toContain('method="POST" action="/authorize"');
    expect(html).toContain(`name="state" value="${escapeHtml(oauth.state)}"`);
    expect(html).not.toContain(oauth.state); // raw quotes/angle brackets never appear
    expect(html).toContain(`name="code_challenge" value="${oauth.code_challenge}"`);
  });

  it("wrong passphrase gives 401 and re-renders the form, with no redirect", async () => {
    const { post } = await boot();
    const res = await post("nope");
    expect(res.status).toBe(401);
    expect(res.headers.get("location")).toBeNull();
    expect(await res.text()).toContain('name="passphrase"');
  });

  it("locks out after 5 failures: the 6th attempt is 429, even with the right passphrase", async () => {
    const { post } = await boot();
    for (let i = 0; i < 5; i++) expect((await post("bad" + i)).status).toBe(401);
    expect((await post("bad5")).status).toBe(429);
    expect((await post(KEY)).status).toBe(429);
  });

  it("counts per client IP using cf-connecting-ip", async () => {
    const { post } = await boot();
    for (let i = 0; i < 5; i++) await post("bad", { "cf-connecting-ip": "203.0.113.1" });
    expect((await post("bad", { "cf-connecting-ip": "203.0.113.1" })).status).toBe(429);
    expect((await post("bad", { "cf-connecting-ip": "203.0.113.2" })).status).toBe(401);
  });

  it("the lockout window expires", async () => {
    const clock = { t: 1_000_000 };
    const { post } = await boot(clock);
    for (let i = 0; i < 5; i++) await post("bad");
    expect((await post("bad")).status).toBe(429);
    clock.t += 15 * 60 * 1000 + 1;
    expect((await post("bad")).status).toBe(401);
  });

  it("right passphrase reaches the SDK handler and redirects with a code and state", async () => {
    const { post, oauth } = await boot();
    const res = await post(KEY);
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get("location")!);
    expect(loc.origin + loc.pathname).toBe(REDIRECT);
    expect(loc.searchParams.get("code")).toBeTruthy();
    expect(loc.searchParams.get("state")).toBe(oauth.state);
  });

  it("a bare GET /authorize with all params never issues a code", async () => {
    const { base, oauth } = await boot();
    const res = await fetch(base + "/authorize?" + new URLSearchParams({ ...oauth, key: KEY, passphrase: KEY }), {
      redirect: "manual",
    });
    expect(res.status).toBe(200);
    expect(res.headers.get("location")).toBeNull();
  });
});

describe("safeCompare", () => {
  it("handles equal, unequal and different-length inputs", () => {
    expect(safeCompare("abc", "abc")).toBe(true);
    expect(safeCompare("abc", "abd")).toBe(false);
    expect(safeCompare("abc", "abcd")).toBe(false);
  });
});
