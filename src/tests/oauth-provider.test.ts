import { describe, it, expect, vi } from "vitest";
import { SingleUserOAuthProvider } from "../oauth-provider.js";

function makeClient(redirectUri: string) {
  return {
    client_id: "test-client",
    client_id_issued_at: Math.floor(Date.now() / 1000),
    redirect_uris: [redirectUri],
  } as any;
}

describe("SingleUserOAuthProvider.authorize", () => {
  const mkRes = (locals: Record<string, unknown> = {}) =>
    ({ locals, status: vi.fn().mockReturnThis(), json: vi.fn(), redirect: vi.fn() }) as any;
  const params = { redirectUri: "https://example.com/cb", codeChallenge: "cc", state: "st" } as any;

  it("rejects with 401 when res.locals.passphraseOk is absent", async () => {
    const provider = new SingleUserOAuthProvider("the-real-key");
    const res = mkRes();
    await provider.authorize(makeClient("https://example.com/cb"), params, res);
    expect(res.redirect).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(401);
  });

  it("ignores a key param (dead path removed)", async () => {
    const provider = new SingleUserOAuthProvider("the-real-key");
    const res = mkRes();
    await provider.authorize(makeClient("https://example.com/cb"), { ...params, key: "the-real-key" }, res);
    expect(res.redirect).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(401);
  });

  it("rejects a truthy-but-not-true flag", async () => {
    const provider = new SingleUserOAuthProvider("the-real-key");
    const res = mkRes({ passphraseOk: "true" });
    await provider.authorize(makeClient("https://example.com/cb"), params, res);
    expect(res.redirect).not.toHaveBeenCalled();
  });

  it("approves and redirects when the consent flag is set", async () => {
    const provider = new SingleUserOAuthProvider("the-real-key");
    const res = mkRes({ passphraseOk: true });
    await provider.authorize(makeClient("https://example.com/cb"), params, res);
    expect(res.redirect).toHaveBeenCalledTimes(1);
    const redirectedTo = new URL(res.redirect.mock.calls[0][0]);
    expect(redirectedTo.searchParams.get("code")).toBeTruthy();
    expect(redirectedTo.searchParams.get("state")).toBe("st");
  });

  it("still rejects an unregistered redirect_uri even with the flag", async () => {
    const provider = new SingleUserOAuthProvider("the-real-key");
    const res = mkRes({ passphraseOk: true });
    await provider.authorize(makeClient("https://example.com/cb"), { ...params, redirectUri: "https://evil.example/cb" }, res);
    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.redirect).not.toHaveBeenCalled();
  });
});

describe("SingleUserOAuthProvider.verifyAccessToken", () => {
  it("accepts the correct token", async () => {
    const provider = new SingleUserOAuthProvider("the-real-key");
    const info = await provider.verifyAccessToken("the-real-key");
    expect(info.token).toBe("the-real-key");
  });

  it("rejects an incorrect token", async () => {
    const provider = new SingleUserOAuthProvider("the-real-key");
    await expect(provider.verifyAccessToken("wrong")).rejects.toThrow("Invalid access token");
  });
});
