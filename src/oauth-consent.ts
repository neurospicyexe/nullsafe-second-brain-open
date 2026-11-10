import { timingSafeEqual } from "crypto";
import type { Request, Response, NextFunction, RequestHandler } from "express";

/**
 * Consent gate for the OAuth /authorize endpoint (single-user server).
 *
 * The MCP SDK's authorize handler never forwards custom params to provider.authorize(),
 * and the provider cannot render UI, so the passphrase check lives in middleware mounted
 * BEFORE mcpAuthRouter. On a correct passphrase it sets res.locals.passphraseOk = true and
 * calls next(); provider.authorize() refuses to issue a code without that flag.
 *
 * Keep this file identical in world-tools-mcp and nullsafe-second-brain.
 */

/** Constant-time compare that does not early-return on a length mismatch. */
export function safeCompare(a: string, b: string): boolean {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) {
    timingSafeEqual(bufA, bufA); // dummy compare, no early-return timing tell
    return false;
  }
  return timingSafeEqual(bufA, bufB);
}

const OAUTH_PARAMS = [
  "client_id",
  "redirect_uri",
  "response_type",
  "code_challenge",
  "code_challenge_method",
  "state",
  "scope",
  "resource",
] as const;

export function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function pick(source: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  if (!source || typeof source !== "object") return out;
  for (const k of OAUTH_PARAMS) {
    const v = (source as Record<string, unknown>)[k];
    if (typeof v === "string") out[k] = v;
  }
  return out;
}

export function renderConsentPage(params: Record<string, string>, error?: string): string {
  const hidden = Object.entries(params)
    .map(([k, v]) => `<input type="hidden" name="${escapeHtml(k)}" value="${escapeHtml(v)}">`)
    .join("\n      ");
  const err = error ? `<p class="err" role="alert">${escapeHtml(error)}</p>` : "";
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>Authorize connection</title>
<style>
  body{font-family:system-ui,sans-serif;max-width:24rem;margin:4rem auto;padding:0 1rem;color:#222}
  input[type=password]{width:100%;box-sizing:border-box;padding:.6rem;margin:.5rem 0 1rem;font-size:1rem}
  button{padding:.6rem 1.2rem;font-size:1rem;cursor:pointer}
  .err{color:#b00020}
</style>
</head>
<body>
  <h1>Authorize connection</h1>
  <p>A client is requesting access to this server. Enter the passphrase to approve.</p>
  ${err}
  <form method="POST" action="/authorize">
      ${hidden}
    <label for="passphrase">Passphrase</label>
    <input id="passphrase" type="password" name="passphrase" autocomplete="current-password" autofocus required>
    <button type="submit">Approve</button>
  </form>
</body>
</html>
`;
}

export interface AuthorizeGateOptions {
  /** The secret the operator must type (the server's API key). */
  passphrase: string;
  maxFailures?: number;
  windowMs?: number;
  now?: () => number;
}

function clientIp(req: Request): string {
  const cf = req.headers["cf-connecting-ip"];
  const v = Array.isArray(cf) ? cf[0] : cf;
  return (v && v.trim()) || req.ip || "unknown";
}

function formActionFor(redirectUri: string | undefined): string {
  // Browsers apply form-action to the redirect that follows a form POST, so the
  // client's redirect origin must be allowed or the final hop is blocked.
  let extra = "";
  if (redirectUri) {
    try {
      const u = new URL(redirectUri);
      if (u.protocol === "https:" || u.protocol === "http:") extra = ` ${u.origin}`;
    } catch {
      /* ignore */
    }
  }
  return `form-action 'self'${extra}`;
}

export function createAuthorizeGate(opts: AuthorizeGateOptions): RequestHandler {
  const max = opts.maxFailures ?? 5;
  const windowMs = opts.windowMs ?? 15 * 60 * 1000;
  const now = opts.now ?? Date.now;
  const failures = new Map<string, { count: number; resetAt: number }>();

  function prune(t: number) {
    if (failures.size < 1000) return;
    for (const [ip, f] of failures) if (f.resetAt <= t) failures.delete(ip);
  }

  return (req: Request, res: Response, next: NextFunction) => {
    if (req.method !== "GET" && req.method !== "POST") return next();

    const isPost = req.method === "POST";
    const body: Record<string, unknown> =
      isPost && req.body && typeof req.body === "object" ? (req.body as Record<string, unknown>) : {};
    const params = pick(isPost ? body : req.query);

    const send = (status: number, error?: string) => {
      res.setHeader("Cache-Control", "no-store");
      res.setHeader("X-Frame-Options", "DENY");
      res.setHeader(
        "Content-Security-Policy",
        `default-src 'none'; style-src 'unsafe-inline'; ${formActionFor(params["redirect_uri"])}`,
      );
      res.status(status).type("html").send(renderConsentPage(params, error));
    };

    const supplied = isPost ? body["passphrase"] : undefined;
    if (typeof supplied !== "string") {
      send(200);
      return;
    }

    const t = now();
    prune(t);
    const ip = clientIp(req);
    let rec = failures.get(ip);
    if (rec && rec.resetAt <= t) {
      failures.delete(ip);
      rec = undefined;
    }
    if (rec && rec.count >= max) {
      res.setHeader("Retry-After", String(Math.ceil((rec.resetAt - t) / 1000)));
      send(429, "Too many failed attempts. Try again later.");
      return;
    }

    if (!safeCompare(supplied, opts.passphrase)) {
      if (!rec) {
        rec = { count: 0, resetAt: t + windowMs };
        failures.set(ip, rec);
      }
      rec.count += 1;
      send(401, "Incorrect passphrase.");
      return;
    }

    failures.delete(ip);
    delete body["passphrase"];
    res.locals["passphraseOk"] = true;
    next();
  };
}
