import { UnsupportedAuthMethodError } from './errors.js';
import { AuthKeyTokenProvider } from './auth-key-token-provider.js';
import { MetadataTokenProvider } from './metadata-token-provider.js';
import {
  StaticCredentialsUnavailableProvider,
  StaticTokenProvider,
} from './static-token-provider.js';
import {
  SUPPORTED_STRATEGIES,
  type AuthStrategyConfig,
  type AuthUsage,
  type TokenProvider,
} from './types.js';

/** AuthManager configuration is a single strategy config. */
export type AuthManagerConfig = AuthStrategyConfig;

function assertSupported(usage: AuthUsage, config: AuthStrategyConfig): void {
  const supported = SUPPORTED_STRATEGIES[usage];
  if (!supported.includes(config.type)) {
    throw new UnsupportedAuthMethodError(usage, config.type, supported);
  }
}

function createProvider(config: AuthStrategyConfig): TokenProvider {
  switch (config.type) {
    case 'iam_token':
      return new StaticTokenProvider(config.token, config.expiresAt, {
        failOnExpiry: true,
      });
    case 'access_token':
      return new StaticTokenProvider(config.token);
    case 'anonymous':
      return new StaticTokenProvider('');
    case 'metadata':
      return new MetadataTokenProvider({
        endpoint: config.endpoint,
        flavor: config.flavor,
      });
    case 'auth_key':
      return new AuthKeyTokenProvider({
        keyId: config.keyId,
        serviceAccountId: config.serviceAccountId,
        privateKey: config.privateKey,
      });
    case 'static':
      // Core cannot exchange login/password without a YDB gRPC endpoint;
      // the @ycforge/auth/ydb adapter delegates to StaticCredentialsProvider.
      return new StaticCredentialsUnavailableProvider();
  }
}

/**
 * Manages a single auth strategy and its token provider.
 *
 * Every `getToken(usage)` call validates that the configured strategy supports
 * the requested usage via the capability matrix.
 */
export class AuthManager {
  /** The configured strategy. */
  readonly config: AuthStrategyConfig;
  #provider: TokenProvider;

  constructor(config: AuthStrategyConfig) {
    this.config = config;
    this.#provider = createProvider(config);
  }

  /**
   * Returns a token for the given usage.
   * Strategy/usage compatibility is validated on every call.
   */
  async getToken(
    usage: AuthUsage,
    options: { force?: boolean; signal?: AbortSignal } = {},
  ): Promise<string> {
    assertSupported(usage, this.config);
    return this.#provider.getToken(options.force, options.signal);
  }

  /**
   * Returns the TokenProvider for the configured strategy. When a usage is
   * given, the returned provider validates strategy/usage compatibility on
   * every getToken() call.
   */
  getProvider(usage?: AuthUsage): TokenProvider {
    if (usage === undefined) {
      return this.#provider;
    }
    return {
      getToken: async (force?: boolean, signal?: AbortSignal) => {
        assertSupported(usage, this.config);
        return this.#provider.getToken(force, signal);
      },
    };
  }
}

/** Creates an AuthManager from a single strategy config. */
export function createAuth(config: AuthStrategyConfig): AuthManager {
  return new AuthManager(config);
}
