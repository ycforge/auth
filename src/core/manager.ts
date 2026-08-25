import {
  AuthConfigurationError,
  UnsupportedAuthMethodError,
} from "./errors.js";
import { AuthKeyTokenProvider } from "./auth-key-token-provider.js";
import { MetadataTokenProvider } from "./metadata-token-provider.js";
import {
  StaticCredentialsUnavailableProvider,
  StaticTokenProvider,
} from "./static-token-provider.js";
import {
  SUPPORTED_STRATEGIES,
  type AuthStrategyConfig,
  type AuthUsage,
  type TokenProvider,
} from "./types.js";

/** A single strategy config or a named map of configs. */
export type AuthManagerConfig =
  AuthStrategyConfig | { configs: Record<string, AuthStrategyConfig> };

const DEFAULT_CONFIG_NAME = "default";

function assertSupported(usage: AuthUsage, config: AuthStrategyConfig): void {
  const supported = SUPPORTED_STRATEGIES[usage];
  if (!supported.includes(config.type)) {
    throw new UnsupportedAuthMethodError(usage, config.type, supported);
  }
}

function createProvider(config: AuthStrategyConfig): TokenProvider {
  switch (config.type) {
    case "iam_token":
      return new StaticTokenProvider(config.token, config.expiresAt, {
        failOnExpiry: true,
      });
    case "access_token":
      return new StaticTokenProvider(config.token);
    case "anonymous":
      return new StaticTokenProvider("");
    case "metadata":
      return new MetadataTokenProvider({
        endpoint: config.endpoint,
        flavor: config.flavor,
      });
    case "auth_key":
      return new AuthKeyTokenProvider({
        keyId: config.keyId,
        serviceAccountId: config.serviceAccountId,
        privateKey: config.privateKey,
      });
    case "static":
      // Core cannot exchange login/password without a YDB gRPC endpoint;
      // the @ycforge/auth/ydb adapter delegates to StaticCredentialsProvider.
      return new StaticCredentialsUnavailableProvider();
  }
}

/**
 * Manages one or more named auth configurations.
 *
 * Config selection order for getToken(usage, configName?):
 * explicit configName → config named after the usage → "default" →
 * the only config (when there is exactly one).
 */
export class AuthManager {
  #configs: Record<string, AuthStrategyConfig>;
  #providers = new Map<string, TokenProvider>();

  constructor(config: AuthManagerConfig) {
    if ("configs" in config && typeof config.configs === "object") {
      const names = Object.keys(config.configs);
      if (names.length === 0) {
        throw new AuthConfigurationError(
          "AuthManager requires at least one named config",
        );
      }
      this.#configs = { ...config.configs };
    } else {
      this.#configs = { [DEFAULT_CONFIG_NAME]: config as AuthStrategyConfig };
    }
  }

  /** Names of all configured auth configurations. */
  get configNames(): string[] {
    return Object.keys(this.#configs);
  }

  /**
   * Resolves the config for a usage / explicit name according to the
   * selection order. Throws AuthConfigurationError when nothing matches.
   */
  resolveConfig(usage?: AuthUsage, configName?: string): AuthStrategyConfig {
    if (configName !== undefined) {
      const config = this.#configs[configName];
      if (!config) {
        throw new AuthConfigurationError(
          `Unknown auth config "${configName}". Available: ${this.configNames.join(", ")}`,
        );
      }
      return config;
    }

    if (usage !== undefined && this.#configs[usage]) {
      return this.#configs[usage];
    }

    if (this.#configs[DEFAULT_CONFIG_NAME]) {
      return this.#configs[DEFAULT_CONFIG_NAME];
    }

    if (this.configNames.length === 1) {
      return this.#configs[this.configNames[0]];
    }

    throw new AuthConfigurationError(
      `No auth config found for usage "${usage ?? "(none)"}" and no "${DEFAULT_CONFIG_NAME}" ` +
        `config is set. Available: ${this.configNames.join(", ")}`,
    );
  }

  #providerFor(name: string, config: AuthStrategyConfig): TokenProvider {
    let provider = this.#providers.get(name);
    if (!provider) {
      provider = createProvider(config);
      this.#providers.set(name, provider);
    }
    return provider;
  }

  /**
   * Returns a token for the given usage.
   * Strategy/usage compatibility is validated on every call.
   */
  async getToken(
    usage: AuthUsage,
    configName?: string,
    options: { force?: boolean; signal?: AbortSignal } = {},
  ): Promise<string> {
    const config = this.resolveConfig(usage, configName);
    assertSupported(usage, config);
    const name = this.#nameOf(config);
    return this.#providerFor(name, config).getToken(
      options.force,
      options.signal,
    );
  }

  /**
   * Returns the TokenProvider for a config. When a usage is given, the
   * returned provider validates strategy/usage compatibility on every
   * getToken() call.
   */
  getProvider(usage?: AuthUsage, configName?: string): TokenProvider {
    const config = this.resolveConfig(usage, configName);
    const name = this.#nameOf(config);
    const provider = this.#providerFor(name, config);
    if (usage === undefined) {
      return provider;
    }
    return {
      getToken: async (force?: boolean, signal?: AbortSignal) => {
        assertSupported(usage, config);
        return provider.getToken(force, signal);
      },
    };
  }

  #nameOf(config: AuthStrategyConfig): string {
    for (const [name, candidate] of Object.entries(this.#configs)) {
      if (candidate === config) return name;
    }
    // Should not happen: resolveConfig returns a stored config object.
    throw new AuthConfigurationError("Resolved config is not registered");
  }
}

/** Creates an AuthManager from a single strategy config or named configs. */
export function createAuth(config: AuthManagerConfig): AuthManager {
  return new AuthManager(config);
}
