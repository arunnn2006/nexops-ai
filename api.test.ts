import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, api, setToken, setUnauthorizedHandler } from "../api";

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

afterEach(() => { vi.unstubAllGlobals(); setUnauthorizedHandler(null); });

describe("api client", () => {
  it("sends the bearer token and query params", async () => {
    setToken("tok123");
    const fetchMock = vi.fn().mockResolvedValue(json(200, { items: [], total: 0 }));
    vi.stubGlobal("fetch", fetchMock);
    await api.incidents({ status: "open", q: "", severity: undefined });
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("/api/v1/incidents?status=open");
    expect(init.headers.Authorization).toBe("Bearer tok123");
  });

  it("normalises server errors", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(json(422, { error: { message: "bad", details: [{ field: "email", message: "invalid" }] } })));
    await expect(api.register("x", "y")).rejects.toMatchObject({ status: 422, message: "bad", details: [{ field: "email", message: "invalid" }] });
  });

  it("reports an unreachable backend", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("fail")));
    await expect(api.services()).rejects.toBeInstanceOf(ApiError);
    await expect(api.services()).rejects.toMatchObject({ status: 0 });
  });

  it("triggers the unauthorized handler on 401 only for authenticated calls", async () => {
    const handler = vi.fn();
    setUnauthorizedHandler(handler);
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(json(401, { error: { message: "Not authenticated" } })));
    setToken("tok");
    await expect(api.services()).rejects.toThrow();
    expect(handler).toHaveBeenCalledTimes(1);
    await expect(api.login("a@b.co", "pw")).rejects.toThrow();
    expect(handler).toHaveBeenCalledTimes(1);
  });

  it("sends the exact confirmation phrase when executing", async () => {
    const fetchMock = vi.fn().mockResolvedValue(json(200, {}));
    vi.stubGlobal("fetch", fetchMock);
    await api.execute(7, "restart_service demo");
    expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toEqual({ confirm: true, confirmation_phrase: "restart_service demo" });
  });
});
