import { AuthError } from "./errors.js";
import {
  BaseTokenProvider,
  isCacheValid,
  parseTimestamp,
  type CachedToken,
} from "./base-token-provider.js";
import type { TokenProvider } from "./types.js";

/**
 * Static token provider: returns the configured token as-is, no refresh.
 *
 * When `expiresAt` is given (iam_token strategy), the token is considered
 * expired once the leeway window is reached and getToken() throws instead
 * of handing out a known-dead token.
 */
export class StaticTokenProvider implements TokenProvider {
  #token: CachedToken;
  #failOnExpiry: boolean;

  constructor(
    token: string,
    expiresAt?: string | number | Date,
    options: { failOnExpiry?: boolean } = {},
  ) {
    this.#token = { value: token, expiresAt: parseTimestamp(expiresAt) };
    this.#failOnExpiry = options.failOnExpiry ?? false;
  }

  getToken(): Promise<string> {
    if (
      this.#failOnExpiry &&
      this.#token.expiresAt !== null &&
      !isCacheValid(this.#token)
    ) {
      return Promise.reject(
        new AuthError(
          "IAM token has expired according to its configured expiresAt; provide a fresh token",
        ),
      );
    }
    return Promise.resolve(this.#token.value);
  }
}

/** Login/password credentials cannot produce a token without a YDB gRPC endpoint. */
export class StaticCredentialsUnavailableProvider extends BaseTokenProvider {
  protected fetchToken(): Promise<CachedToken> {
    return Promise.reject(
      new AuthError(
        'The "static" (username/password) strategy cannot fetch a token without a YDB endpoint. ' +
          'Use createYdbCredentialsProvider() from "@ycforge/auth/ydb", which delegates to ' +
          "StaticCredentialsProvider from @ydbjs/auth.",
      ),
    );
  }
}
