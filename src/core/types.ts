/**
 * A provider that yields an authentication token.
 * Implementations may cache and refresh the token internally.
 */
export interface TokenProvider {
  getToken(force?: boolean, signal?: AbortSignal): Promise<string>;
}

/** Usage scope for Yandex Cloud APIs (e.g. KMS). */
export const YCLOUD_AUTH_USAGE = 'ycloud' as const;

/** Usage scope for YDB. */
export const YDB_AUTH_USAGE = 'ydb' as const;

/** Where the token will be used: generic Yandex Cloud API or YDB. */
export type AuthUsage = typeof YCLOUD_AUTH_USAGE | typeof YDB_AUTH_USAGE;

export type AuthStrategyType = AuthStrategyConfig['type'];

export type AuthStrategyConfig =
  | {
      /** Static IAM token, returned as-is. */
      type: 'iam_token';
      token: string;
      /** Optional known expiry (Date, ISO string or unix ms/s). Once passed, getToken() throws. */
      expiresAt?: string | number | Date;
    }
  | {
      /** Yandex Cloud VM metadata service. */
      type: 'metadata';
      endpoint?: string;
      /** Metadata flavor header value (default: "Google"). */
      flavor?: string;
    }
  | {
      /** Service account authorized key: JWT (PS256) exchanged for an IAM token. */
      type: 'auth_key';
      keyId: string;
      serviceAccountId: string;
      privateKey: string;
    }
  | {
      /** Static access token (YDB only). */
      type: 'access_token';
      token: string;
    }
  | {
      /** Anonymous access, empty token (YDB only). */
      type: 'anonymous';
    }
  | {
      /** Static username/password credentials (YDB only, resolved via the ydb adapter). */
      type: 'static';
      username: string;
      password: string;
    };

/** Strategy types supported by each usage. */
export const SUPPORTED_STRATEGIES: Readonly<
  Record<AuthUsage, readonly AuthStrategyType[]>
> = {
  [YCLOUD_AUTH_USAGE]: ['iam_token', 'metadata', 'auth_key'],
  [YDB_AUTH_USAGE]: [
    'iam_token',
    'metadata',
    'auth_key',
    'access_token',
    'anonymous',
    'static',
  ],
};
