import { describe, expect, it } from "vitest";

import {
  accessRequestPath,
  afterNoAccess,
  afterRefusedAccept,
  needsConfirmation,
  shouldRestore,
  start,
  tenantToEnter,
} from "./flow";
import { path, requestId, requester, type LoginRequest } from "./login-request";
import { apiBase } from "./api";
import { decode, encode } from "./base64url";

const request = (prompt?: string, extra: Partial<LoginRequest> = {}): LoginRequest => ({
  client_id: "kubernetes",
  scopes: ["openid"],
  prompt: prompt ?? null,
  ...extra,
});

describe("requestId", () => {
  it("takes an id", () => {
    expect(requestId("?login_request=0193a2f1-7c1e-7000-8000-000000000000")).toEqual({
      id: "0193a2f1-7c1e-7000-8000-000000000000",
      invalid: false,
    });
  });
  it("has none without the parameter", () => {
    expect(requestId("")).toEqual({ id: null, invalid: false });
  });
  it.each(["../../sign-out", "a/b", "a?b", "a#b", "", "a b", "..", "x".repeat(201)])(
    "refuses %j, which could aim calls elsewhere",
    (id) => {
      expect(requestId(`?login_request=${encodeURIComponent(id)}`)).toEqual({ id: null, invalid: true });
    },
  );
});

describe("start", () => {
  it("accepts at once when someone is signed in", () => {
    expect(start(request(), false, true)).toEqual({ kind: "accept" });
  });
  it("answers prompt=none with login_required when nobody is", () => {
    expect(start(request("none"), false, false)).toEqual({ kind: "reject", error: "login_required" });
  });
  it("asks for a sign-in otherwise", () => {
    expect(start(request(), false, false)).toEqual({ kind: "sign-in" });
    expect(start(request("login consent"), false, false)).toEqual({ kind: "sign-in" });
  });
  it("shows the account without a request", () => {
    expect(start(null, false, true)).toEqual({ kind: "account" });
    expect(start(null, false, false)).toEqual({ kind: "sign-in" });
  });
  it("says when the request is gone", () => {
    expect(start(null, true, true)).toEqual({ kind: "expired" });
  });
});

describe("prompt=login", () => {
  it("never reuses a sign-in", () => {
    expect(shouldRestore(request("login"))).toBe(false);
    expect(shouldRestore(request("consent"))).toBe(true);
    expect(shouldRestore(null)).toBe(true);
  });
});

describe("afterRefusedAccept", () => {
  it("shows nothing for prompt=none", () => {
    expect(afterRefusedAccept(request("none"))).toEqual({ kind: "reject", error: "login_required" });
  });
  it("asks for a new sign-in otherwise", () => {
    expect(afterRefusedAccept(request())).toEqual({ kind: "sign-in" });
  });
});

describe("tenantToEnter", () => {
  it("enters the requested tenant", () => {
    expect(tenantToEnter(request(undefined, { tenant: "t1" }), undefined)).toBe("t1");
    expect(tenantToEnter(request(undefined, { tenant: "t1" }), "t2")).toBe("t1");
  });
  it("stays where it is otherwise", () => {
    expect(tenantToEnter(request(undefined, { tenant: "t1" }), "t1")).toBeNull();
    expect(tenantToEnter(request(), "t1")).toBeNull();
    expect(tenantToEnter(null, undefined)).toBeNull();
  });
});

// r[verify oidc.provider.login-page.access-requests]
describe("afterNoAccess", () => {
  it("offers to request access when the server takes requests", () => {
    expect(afterNoAccess(request(undefined, { tenant: "t1" }), true)).toEqual({ kind: "ask" });
  });
  it("asks for another sign-in when it doesn't", () => {
    expect(afterNoAccess(request(undefined, { tenant: "t1" }), false)).toEqual({ kind: "sign-in" });
  });
  it("shows nothing for prompt=none", () => {
    expect(afterNoAccess(request("none", { tenant: "t1" }), true)).toEqual({ kind: "reject", error: "login_required" });
  });
  it("names the tenant in the path, escaped", () => {
    expect(accessRequestPath("root")).toBe("/tenants/root/access-request");
    expect(accessRequestPath("a/../b")).toBe("/tenants/a%2F..%2Fb/access-request");
  });
});

describe("apiBase", () => {
  it("is the page's parent", () => {
    expect(apiBase(new URL("https://id.example/login/?login_request=x")).href).toBe("https://id.example/");
    expect(apiBase(new URL("https://id.example/login/index.html")).href).toBe("https://id.example/");
  });
  it("keeps a proxy's prefix", () => {
    expect(apiBase(new URL("https://example.com/sso/login/")).href).toBe("https://example.com/sso/");
  });
});

describe("base64url", () => {
  it("round-trips without padding", () => {
    const bytes = new Uint8Array([0xfb, 0xff, 0x00, 0x10]);
    expect(encode(bytes)).toBe("-_8AEA");
    expect([...decode("-_8AEA")]).toEqual([...bytes]);
  });
});

// r[verify session.native-handoff.confirm]
describe("native requests", () => {
  const native: LoginRequest = { kind: "native", app: "konklav-cli" };
  it("ask before accepting, even when signed in", () => {
    expect(start(native, false, true)).toEqual({ kind: "accept" });
    expect(needsConfirmation(native, false)).toBe(true);
    expect(needsConfirmation(native, true)).toBe(false);
  });
  it("don't ask for OIDC requests", () => {
    expect(needsConfirmation(request(), false)).toBe(false);
    expect(needsConfirmation({ kind: "oidc", client_id: "kubernetes" }, false)).toBe(false);
  });
  it("name the app", () => {
    expect(requester(native)).toBe("konklav-cli");
    expect(requester(request())).toBe("kubernetes");
  });
  it("have no tenant to enter", () => {
    expect(tenantToEnter(native, undefined)).toBeNull();
  });
});

// r[verify session.login-requests.paths]
describe("path", () => {
  it("uses the neutral login-request paths", () => {
    expect(path("0193a2f1-7c1e-7000-8000-000000000000")).toBe(
      "/login-requests/0193a2f1-7c1e-7000-8000-000000000000",
    );
  });
});
