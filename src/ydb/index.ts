import type { ChannelOptions } from '@grpc/grpc-js';
import { CredentialsProvider } from '@ydbjs/auth';
import { AnonymousCredentialsProvider } from '@ydbjs/auth/anonymous';
import { StaticCredentialsProvider } from '@ydbjs/auth/static';

import { AuthConfigurationError } from '../core/errors.js';
import type { AuthManager } from '../core/manager.js';
import { YDB_AUTH_USAGE, type AuthUsage } from '../core/types.js';

/** Options for the YDB credentials adapter. */
export interface YdbCredentialsAdapterOptions {
  /**
   * YDB endpoint (e.g. "grpcs://ydb.serverless.yandexcloud.net:2135").
   * Required for the "static" (username/password) strategy, which logs in
   * over gRPC; ignored by other strategies.
   */
  endpoint?: string;
  /**
   * Use a TLS secure channel for the static-strategy login request
   * (default: true). Set to false for local insecure YDB.
   */
  secure?: boolean;
  /** Extra gRPC channel options for the static strategy. */
  channelOptions?: ChannelOptions;
}

/**
 * CredentialsProvider delegating every getToken() call to the AuthManager
 * with the requested usage.
 */
class YdbAdapterCredentialsProvider extends CredentialsProvider {
  #auth: AuthManager;
  #usage: AuthUsage;

  constructor(auth: AuthManager, usage: AuthUsage) {
    super();
    this.#auth = auth;
    this.#usage = usage;
  }

  getToken(force?: boolean, signal?: AbortSignal): Promise<string> {
    return this.#auth.getToken(this.#usage, { force, signal });
  }
}

/**
 * Adapts an AuthManager to a @ydbjs/auth CredentialsProvider usable with
 * the ydb-js-sdk driver.
 *
 * @param auth - AuthManager to adapt.
 * @param usage - Target usage scope ('ydb' or 'ycloud'). Passed to every
 *   getToken() call so the manager can validate strategy/usage compatibility.
 * @param options - Optional settings; endpoint/secure/channelOptions are only
 *   used by the 'static' strategy.
 *
 * - "static" (username/password) → StaticCredentialsProvider from
 *   @ydbjs/auth (requires options.endpoint; it performs the gRPC login).
 *   Only allowed with usage 'ydb'.
 * - "anonymous" → AnonymousCredentialsProvider from @ydbjs/auth.
 * - everything else → a thin CredentialsProvider delegating getToken() to
 *   auth.getToken(usage), including usage validation.
 */
export function createYdbCredentialsProvider(
  auth: AuthManager,
  usage: AuthUsage,
  options: YdbCredentialsAdapterOptions = {},
): CredentialsProvider {
  const config = auth.config;

  if (config.type === 'static') {
    if (usage !== YDB_AUTH_USAGE) {
      throw new AuthConfigurationError(
        'The "static" (username/password) strategy can only be used with YDB usage ' +
          `(${YDB_AUTH_USAGE}), got "${usage}".`,
      );
    }
    if (!options.endpoint) {
      throw new AuthConfigurationError(
        'The "static" (username/password) strategy requires options.endpoint ' +
          '(e.g. "grpcs://ydb.serverless.yandexcloud.net:2135") to log in over gRPC',
      );
    }
    const secure = options.secure ?? true;
    return new StaticCredentialsProvider(
      { username: config.username, password: config.password },
      options.endpoint,
      secure ? {} : undefined,
      options.channelOptions,
    );
  }

  if (config.type === 'anonymous') {
    return new AnonymousCredentialsProvider();
  }

  return new YdbAdapterCredentialsProvider(auth, usage);
}
