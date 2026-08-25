import crypto from 'node:crypto';

import { AuthConfigurationError, AuthError } from './errors.js';
import { markNonRetryable, retry, type RetryOptions } from './retry.js';
import {
  BaseTokenProvider,
  parseTimestamp,
  type CachedToken,
} from './base-token-provider.js';

export const IAM_TOKEN_URL = 'https://iam.api.cloud.yandex.net/iam/v1/tokens';

/** Timeout of a single IAM token-exchange HTTP request. */
const IAM_FETCH_TIMEOUT_MS = 10_000;

/**
 * Default cache TTL when the IAM response omits expiresAt.
 * Matches the actual IAM token lifetime (1 hour).
 */
const DEFAULT_TOKEN_TTL_MS = 3600_000;

export interface AuthKeyCredentials {
  keyId: string;
  serviceAccountId: string;
  privateKey: string;
}

export interface AuthKeyTokenProviderOptions {
  /** Timeout of a single fetch to IAM, ms (default: 10 000). */
  fetchTimeoutMs?: number;
  /**
   * Retry tuning for the IAM exchange. Defaults: 5 attempts,
   * base delay 100 ms, backoff factor 10.
   */
  retry?: Pick<RetryOptions, 'attempts' | 'baseDelayMs' | 'factor'>;
}

interface IamTokenResponse {
  iamToken?: string;
  expiresAt?: unknown;
}

function errorName(err: unknown): string {
  if (typeof err === 'object' && err !== null) {
    const name: unknown = (err as { name?: unknown }).name;
    return typeof name === 'string' ? name : '';
  }
  return '';
}

/**
 * Exchanges a service account authorized key for an IAM token:
 * builds a PS256-signed JWT and POSTs it to the Yandex Cloud IAM API.
 * The token is cached with a 60s leeway and refreshed single-flight.
 * HTTP error response bodies are never logged (they may leak secrets).
 */
export class AuthKeyTokenProvider extends BaseTokenProvider {
  #credentials: AuthKeyCredentials;
  #fetchTimeoutMs: number;
  #retry?: Pick<RetryOptions, 'attempts' | 'baseDelayMs' | 'factor'>;

  constructor(
    credentials: AuthKeyCredentials,
    options: AuthKeyTokenProviderOptions = {},
  ) {
    super();
    this.#credentials = credentials;
    this.#fetchTimeoutMs = options.fetchTimeoutMs ?? IAM_FETCH_TIMEOUT_MS;
    this.#retry = options.retry;
    if (!(this.#fetchTimeoutMs > 0)) {
      throw new AuthConfigurationError(
        'fetchTimeoutMs must be a positive number',
      );
    }
  }

  protected async fetchToken(signal?: AbortSignal): Promise<CachedToken> {
    return retry(
      async (attemptSignal) => {
        const jwt = this.#generateJWT();

        let response: Response;
        try {
          response = await fetch(IAM_TOKEN_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ jwt }),
            signal: this.#withFetchTimeout(attemptSignal),
          });
        } catch (err) {
          throw this.#normalizeFetchError(err);
        }

        if (!response.ok) {
          // Response body is intentionally not read: it may contain
          // sensitive content and must never end up in logs.
          throw new AuthError(
            `IAM token exchange failed with status ${response.status}`,
          );
        }

        let payload: IamTokenResponse;
        try {
          payload = (await response.json()) as IamTokenResponse;
        } catch (err) {
          // Invalid JSON is deterministic — do not retry, do not trust the body.
          throw markNonRetryable(
            new AuthError(
              'IAM token exchange failed: response is not valid JSON',
              {
                cause: err,
              },
            ),
          );
        }

        if (typeof payload.iamToken !== 'string' || payload.iamToken === '') {
          throw markNonRetryable(
            new AuthError('IAM token exchange failed: no iamToken in response'),
          );
        }

        let expiresAt: Date | null;
        try {
          expiresAt = parseTimestamp(payload.expiresAt);
        } catch (err) {
          throw markNonRetryable(err as Error);
        }
        if (expiresAt === null) {
          const fallback = new Date(Date.now() + DEFAULT_TOKEN_TTL_MS);
          console.warn(
            `[ycforge-auth] IAM response is missing expiresAt; assuming default ` +
              `token TTL ${DEFAULT_TOKEN_TTL_MS} ms (until ${fallback.toISOString()})`,
          );
          expiresAt = fallback;
        }

        return { value: payload.iamToken, expiresAt };
      },
      {
        ...this.#retry,
        signal,
        onRetry: (attempt, err, delayMs) => {
          console.warn(
            `[ycforge-auth] IAM token exchange attempt ${attempt} failed ` +
              `(${err instanceof Error ? err.message : String(err)}), ` +
              `retrying in ${delayMs} ms`,
          );
        },
      },
    );
  }

  #withFetchTimeout(signal?: AbortSignal): AbortSignal {
    const timeout = AbortSignal.timeout(this.#fetchTimeoutMs);
    return signal ? AbortSignal.any([signal, timeout]) : timeout;
  }

  #normalizeFetchError(err: unknown): Error {
    const errName = errorName(err);

    if (errName === 'TimeoutError') {
      const error = new AuthError(
        `IAM token exchange timed out after ${this.#fetchTimeoutMs} ms`,
      );
      error.name = 'TimeoutError';
      return error;
    }
    if (errName === 'AbortError') {
      const message =
        err instanceof Error && err.message
          ? err.message
          : 'IAM token exchange aborted';
      const error = new AuthError(message);
      error.name = 'AbortError';
      if (err instanceof Error && err.stack) error.stack = err.stack;
      return error;
    }

    const baseMessage = err instanceof Error ? err.message : String(err);
    const error = new AuthError(`IAM token exchange failed: ${baseMessage}`);
    if (err instanceof Error && err.stack) error.stack = err.stack;
    return error;
  }

  #generateJWT(): string {
    const now = Math.floor(Date.now() / 1000);

    const header = {
      alg: 'PS256',
      typ: 'JWT',
      kid: this.#credentials.keyId,
    };

    const payload = {
      iss: this.#credentials.serviceAccountId,
      sub: this.#credentials.serviceAccountId,
      aud: IAM_TOKEN_URL,
      iat: now,
      exp: now + 3600,
    };

    const encodedHeader = Buffer.from(JSON.stringify(header)).toString(
      'base64url',
    );
    const encodedPayload = Buffer.from(JSON.stringify(payload)).toString(
      'base64url',
    );
    const signingInput = `${encodedHeader}.${encodedPayload}`;

    const privateKey = crypto.createPrivateKey(this.#credentials.privateKey);
    const signature = crypto.sign('sha256', Buffer.from(signingInput), {
      key: privateKey,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
    });

    return `${signingInput}.${signature.toString('base64url')}`;
  }
}
