import { jest } from "@jest/globals";

import {
  AuthError,
  MetadataTokenProvider,
  StaticTokenProvider,
  TOKEN_EXPIRY_LEEWAY_MS,
} from "../src/index.js";

const originalFetch = globalThis.fetch;

function jsonResponse(data: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: () => Promise.resolve(data),
    text: () => Promise.resolve(JSON.stringify(data)),
  } as Response;
}

function mockFetch(impl: () => Promise<Response>) {
  globalThis.fetch = jest.fn(impl);
  return globalThis.fetch as jest.MockedFunction<typeof fetch>;
}

afterEach(() => {
  globalThis.fetch = originalFetch;
  jest.restoreAllMocks();
});

describe("StaticTokenProvider", () => {
  it("returns the token as-is without fetch", async () => {
    const fetchMock = mockFetch(() => Promise.reject(new Error("no network")));
    const provider = new StaticTokenProvider("tok");

    await expect(provider.getToken()).resolves.toBe("tok");
    await expect(provider.getToken(true)).resolves.toBe("tok");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("returns token without expiry forever", async () => {
    const provider = new StaticTokenProvider("tok", undefined, {
      failOnExpiry: true,
    });
    await expect(provider.getToken()).resolves.toBe("tok");
  });

  it("throws when expiresAt has passed (failOnExpiry)", async () => {
    const provider = new StaticTokenProvider("tok", Date.now() - 1000, {
      failOnExpiry: true,
    });
    await expect(provider.getToken()).rejects.toThrow(AuthError);
    await expect(provider.getToken()).rejects.toThrow(/expired/);
  });

  it("accepts ISO string and unix-seconds expiresAt", async () => {
    const futureIso = new Date(Date.now() + 3600_000).toISOString();
    await expect(
      new StaticTokenProvider("a", futureIso, {
        failOnExpiry: true,
      }).getToken(),
    ).resolves.toBe("a");

    const futureSec = Math.floor((Date.now() + 3600_000) / 1000);
    await expect(
      new StaticTokenProvider("b", futureSec, {
        failOnExpiry: true,
      }).getToken(),
    ).resolves.toBe("b");
  });

  it("throws on invalid expiresAt at construction", () => {
    expect(() => new StaticTokenProvider("tok", "not-a-date")).toThrow(
      AuthError,
    );
  });
});

describe("MetadataTokenProvider", () => {
  it("fetches token from the metadata service with the flavor header", async () => {
    const fetchMock = mockFetch(() =>
      Promise.resolve(
        jsonResponse({ access_token: "meta-token", expires_in: 3600 }),
      ),
    );

    const provider = new MetadataTokenProvider();
    await expect(provider.getToken()).resolves.toBe("meta-token");

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as unknown as [
      string,
      RequestInit,
    ];
    expect(url).toContain("169.254.169.254");
    expect((init.headers as Record<string, string>)["Metadata-Flavor"]).toBe(
      "Google",
    );
  });

  it("supports custom endpoint and flavor", async () => {
    const fetchMock = mockFetch(() =>
      Promise.resolve(jsonResponse({ access_token: "t", expires_in: 100 })),
    );
    const provider = new MetadataTokenProvider({
      endpoint: "http://custom.local/token",
      flavor: "Custom",
    });
    await provider.getToken();
    const [url, init] = fetchMock.mock.calls[0] as unknown as [
      string,
      RequestInit,
    ];
    expect(url).toBe("http://custom.local/token");
    expect((init.headers as Record<string, string>)["Metadata-Flavor"]).toBe(
      "Custom",
    );
  });

  it("caches the token (no second fetch)", async () => {
    const fetchMock = mockFetch(() =>
      Promise.resolve(
        jsonResponse({ access_token: "meta-token", expires_in: 3600 }),
      ),
    );
    const provider = new MetadataTokenProvider();

    await provider.getToken();
    await provider.getToken();
    await provider.getToken();
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("refreshes after expiry minus leeway", async () => {
    let now = Date.now();
    const nowSpy = jest.spyOn(Date, "now").mockImplementation(() => now);
    const fetchMock = mockFetch(() =>
      Promise.resolve(jsonResponse({ access_token: "t", expires_in: 3600 })),
    );

    const provider = new MetadataTokenProvider();
    await provider.getToken();

    now += 3600_000 - TOKEN_EXPIRY_LEEWAY_MS + 1;
    await provider.getToken();
    expect(fetchMock).toHaveBeenCalledTimes(2);
    nowSpy.mockRestore();
  });

  it("deduplicates concurrent getToken calls (single-flight)", async () => {
    let resolveResponse: (r: Response) => void = () => {};
    const fetchMock = mockFetch(
      () =>
        new Promise<Response>((resolve) => {
          resolveResponse = resolve;
        }),
    );
    const provider = new MetadataTokenProvider();

    const p1 = provider.getToken();
    const p2 = provider.getToken();
    resolveResponse(jsonResponse({ access_token: "t", expires_in: 3600 }));

    await expect(p1).resolves.toBe("t");
    await expect(p2).resolves.toBe("t");
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("drops the cache when refresh fails and retries", async () => {
    jest.useFakeTimers();
    try {
      let calls = 0;
      const fetchMock = mockFetch(() => {
        calls++;
        return calls === 1
          ? Promise.resolve(
              jsonResponse({ access_token: "first", expires_in: 3600 }),
            )
          : Promise.reject(new Error("network down"));
      });

      const provider = new MetadataTokenProvider();
      await expect(provider.getToken()).resolves.toBe("first");

      const failing = provider.getToken(true);
      const assertion = expect(failing).rejects.toThrow(/network down/);
      await jest.runAllTimersAsync();
      await assertion;
      expect(fetchMock.mock.calls.length).toBeGreaterThan(1);

      // Cache was cleared: next call retries the network instead of
      // serving the stale token.
      const again = provider.getToken();
      const againAssertion = expect(again).rejects.toThrow(/network down/);
      await jest.runAllTimersAsync();
      await againAssertion;
    } finally {
      jest.useRealTimers();
    }
  });

  it("does not leak the response body on HTTP errors", async () => {
    jest.useFakeTimers();
    try {
      const warnSpy = jest.spyOn(console, "warn").mockImplementation(() => {});
      mockFetch(() =>
        Promise.resolve({
          ok: false,
          status: 403,
          json: () => Promise.resolve({ secret: "TOP-SECRET-BODY" }),
          text: () => Promise.resolve("TOP-SECRET-BODY"),
        } as unknown as Response),
      );

      const provider = new MetadataTokenProvider();
      const promise = provider.getToken();
      const assertion = expect(promise).rejects.toThrow(/status 403/);
      await jest.runAllTimersAsync();
      await assertion;

      const logged = warnSpy.mock.calls.flat().join(" ");
      expect(logged).not.toContain("TOP-SECRET-BODY");
      warnSpy.mockRestore();
    } finally {
      jest.useRealTimers();
    }
  });

  it("fails fast when access_token is missing (retried: transient metadata issues)", async () => {
    jest.useFakeTimers();
    try {
      const fetchMock = mockFetch(() =>
        Promise.resolve(jsonResponse({ expires_in: 3600 })),
      );
      const provider = new MetadataTokenProvider();
      const promise = provider.getToken();
      const assertion = expect(promise).rejects.toThrow(/access_token/);
      await jest.runAllTimersAsync();
      await assertion;
      expect(fetchMock.mock.calls.length).toBe(5);
    } finally {
      jest.useRealTimers();
    }
  });
});
