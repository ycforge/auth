import type { ChannelOptions } from '@grpc/grpc-js';
import { CredentialsProvider } from '@ydbjs/auth';
import { AnonymousCredentialsProvider } from '@ydbjs/auth/anonymous';
import { StaticCredentialsProvider } from '@ydbjs/auth/static';

import { AuthConfigurationError } from '../core/errors.js';
import type { AuthManager } from '../core/manager.js';

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
 * with usage "ydb".
 */
class YdbAdapterCredentialsProvider extends CredentialsProvider {
  #auth: AuthManager;

  constructor(auth: AuthManager) {
    super();
    this.#auth = auth;
  }

  getToken(force?: boolean, signal?: AbortSignal): Promise<string> {
    return this.#auth.getToken('ydb', { force, signal });
  }
}

/**
 * Adapts an AuthManager to a @ydbjs/auth CredentialsProvider usable with
 * the ydb-js-sdk driver.
 *
 * - "static" (username/password) → StaticCredentialsProvider from
 *   @ydbjs/auth (requires options.endpoint; it performs the gRPC login).
 * - "anonymous" → AnonymousCredentialsProvider from @ydbjs/auth.
 * - everything else → a thin CredentialsProvider delegating getToken() to
 *   auth.getToken('ydb'), including usage validation.
 */
export function createYdbCredentialsProvider(
  auth: AuthManager,
  options: YdbCredentialsAdapterOptions = {},
): CredentialsProvider {
  const config = auth.config;

  if (config.type === 'static') {
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

  return new YdbAdapterCredentialsProvider(auth);
}
