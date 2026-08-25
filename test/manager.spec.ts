import { jest } from "@jest/globals";

import {
  AuthConfigurationError,
  AuthError,
  UnsupportedAuthMethodError,
  createAuth,
  type AuthStrategyConfig,
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

afterEach(() => {
  globalThis.fetch = originalFetch;
  jest.restoreAllMocks();
});

const ALL_STRATEGIES: Record<string, AuthStrategyConfig> = {
  iam_token: { type: "iam_token", token: "t" },
  metadata: { type: "metadata" },
  auth_key: {
    type: "auth_key",
    keyId: "k",
    serviceAccountId: "sa",
    privateKey: "pk",
  },
  access_token: { type: "access_token", token: "t" },
  anonymous: { type: "anonymous" },
  static: { type: "static", username: "u", password: "p" },
};

describe("capability matrix", () => {
  const ycloudOnly = ["access_token", "anonymous", "static"];

  for (const name of ycloudOnly) {
    it(`rejects "${name}" for usage "ycloud"`, async () => {
      const auth = createAuth(ALL_STRATEGIES[name]);
      await expect(auth.getToken("ycloud")).rejects.toThrow(
        UnsupportedAuthMethodError,
      );
      const err = await auth.getToken("ycloud").catch((e: unknown) => e);
      expect(err).toBeInstanceOf(UnsupportedAuthMethodError);
      const unsupported = err as UnsupportedAuthMethodError;
      expect(unsupported.message).toContain("ycloud");
      expect(unsupported.message).toContain(name);
      expect(unsupported.message).toContain("iam_token");
      expect(unsupported.message).toContain("metadata");
      expect(unsupported.message).toContain("auth_key");
    });
  }

  it('supports iam_token/metadata/auth_key for "ycloud"', async () => {
    await expect(
      createAuth({ type: "iam_token", token: "tok" }).getToken("ycloud"),
    ).resolves.toBe("tok");

    globalThis.fetch = jest.fn(() =>
      Promise.resolve(jsonResponse({ access_token: "meta", expires_in: 3600 })),
    );
    await expect(
      createAuth({ type: "metadata" }).getToken("ycloud"),
    ).resolves.toBe("meta");
  });

  it('supports static strategies for "ydb"', async () => {
    await expect(
      createAuth({ type: "access_token", token: "at" }).getToken("ydb"),
    ).resolves.toBe("at");
    await expect(
      createAuth({ type: "anonymous" }).getToken("ydb"),
    ).resolves.toBe("");
    await expect(
      createAuth({ type: "iam_token", token: "it" }).getToken("ydb"),
    ).resolves.toBe("it");
  });

  it('core "static" strategy explains the ydb adapter is required', async () => {
    const auth = createAuth({ type: "static", username: "u", password: "p" });
    const err = await auth.getToken("ydb").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(AuthError);
    expect((err as Error).message).toContain("@ycforge/auth/ydb");
    expect((err as Error).message).toContain("StaticCredentialsProvider");
  });

  it("getProvider validates usage compatibility", async () => {
    const auth = createAuth({ type: "anonymous" });
    const provider = auth.getProvider("ycloud");
    await expect(provider.getToken()).rejects.toThrow(
      UnsupportedAuthMethodError,
    );
  });
});

describe("AuthManager config selection", () => {
  it("single config: used for any usage", async () => {
    const auth = createAuth({ type: "iam_token", token: "single" });
    await expect(auth.getToken("ycloud")).resolves.toBe("single");
    await expect(auth.getToken("ydb")).resolves.toBe("single");
  });

  it("picks the config named after the usage", async () => {
    const auth = createAuth({
      configs: {
        ycloud: { type: "iam_token", token: "cloud-token" },
        ydb: { type: "access_token", token: "db-token" },
      },
    });
    await expect(auth.getToken("ycloud")).resolves.toBe("cloud-token");
    await expect(auth.getToken("ydb")).resolves.toBe("db-token");
  });

  it('falls back to "default"', async () => {
    const auth = createAuth({
      configs: {
        default: { type: "iam_token", token: "def" },
        ydb: { type: "access_token", token: "db" },
      },
    });
    await expect(auth.getToken("ycloud")).resolves.toBe("def");
    await expect(auth.getToken("ydb")).resolves.toBe("db");
  });

  it("explicit config name wins over usage/default", async () => {
    const auth = createAuth({
      configs: {
        default: { type: "iam_token", token: "def" },
        other: { type: "iam_token", token: "other-token" },
      },
    });
    await expect(auth.getToken("ycloud", "other")).resolves.toBe("other-token");
  });

  it("single non-default config is used as a fallback", async () => {
    const auth = createAuth({
      configs: { only: { type: "iam_token", token: "only-token" } },
    });
    await expect(auth.getToken("ycloud")).resolves.toBe("only-token");
  });

  it("throws a clear error when nothing matches", async () => {
    const auth = createAuth({
      configs: {
        a: { type: "iam_token", token: "a" },
        b: { type: "iam_token", token: "b" },
      },
    });
    await expect(auth.getToken("ycloud")).rejects.toThrow(
      AuthConfigurationError,
    );
    await expect(auth.getToken("ycloud")).rejects.toThrow(/a, b/);
  });

  it("throws on unknown explicit config name", async () => {
    const auth = createAuth({ type: "iam_token", token: "t" });
    await expect(auth.getToken("ycloud", "nope")).rejects.toThrow(
      /Unknown auth config "nope"/,
    );
  });

  it("throws on an empty configs map", () => {
    expect(() => createAuth({ configs: {} })).toThrow(AuthConfigurationError);
  });

  it("validates support per explicit config at getToken time", async () => {
    const auth = createAuth({
      configs: {
        ycloud: { type: "iam_token", token: "ok" },
        login: { type: "static", username: "u", password: "p" },
      },
    });
    await expect(auth.getToken("ycloud", "login")).rejects.toThrow(
      UnsupportedAuthMethodError,
    );
  });
});
