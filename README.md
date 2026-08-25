# @ycforge/auth

Shared authentication logic for Yandex Cloud APIs and YDB, extracted from
`@ycforge/ydb-orm` and `@ycforge/yandex-kms-orm-provider`.

- Zero runtime dependencies in the core (Node builtins + global `fetch` only).
- Token caching with 60s leeway and single-flight refresh.
- Small built-in exponential-backoff retry (5 attempts, base 100 ms, factor 10).
- Capability matrix: each token request is validated against the target usage.
- Optional adapters: `@ydbjs/auth` (YDB driver) and NestJS.

Requires Node.js >= 22 (ESM).

## Installation

```bash
yarn add @ycforge/auth
# optional, for the YDB adapter:
yarn add @ydbjs/auth
# optional, for the NestJS module:
yarn add @nestjs/common reflect-metadata
```

## Quick start

```ts
import { createAuth } from '@ycforge/auth';

const auth = createAuth({ type: 'metadata' });
const token = await auth.getToken('ycloud');
```

## Strategies

### `iam_token` — static IAM token

```ts
const auth = createAuth({
  type: 'iam_token',
  token: process.env.IAM_TOKEN!,
  // optional: once this time passes, getToken() throws instead of
  // handing out a known-dead token (Date, ISO string or unix s/ms)
  expiresAt: '2026-09-01T00:00:00Z',
});
```

### `metadata` — VM metadata service

```ts
const auth = createAuth({
  type: 'metadata',
  // defaults shown below:
  endpoint:
    'http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token',
  flavor: 'Google',
});
```

### `auth_key` — service account authorized key

Signs a PS256 JWT and exchanges it for an IAM token at
`https://iam.api.cloud.yandex.net/iam/v1/tokens` (10s per-request timeout,
retry with backoff, HTTP error bodies are never logged).

```ts
import { createAuth, authKeyFromFile } from '@ycforge/auth';

const auth = createAuth(authKeyFromFile('./authorized_key.json'));
// or inline:
const auth2 = createAuth({
  type: 'auth_key',
  keyId: 'aje...',
  serviceAccountId: 'sa-...',
  privateKey: process.env.PRIVATE_KEY!,
});
```

### `access_token` / `anonymous` / `static` (YDB only)

```ts
createAuth({ type: 'access_token', token: '...' });
createAuth({ type: 'anonymous' }); // empty token
createAuth({ type: 'static', username: 'user', password: 'pass' });
```

The `static` (username/password) strategy cannot fetch a token without a YDB
gRPC endpoint: in the core its `getToken()` throws with a hint to use the
`@ycforge/auth/ydb` adapter, which delegates to `StaticCredentialsProvider`
from `@ydbjs/auth`.

## Capability matrix

| Strategy       | `ycloud` | `ydb` |
| -------------- | -------- | ----- |
| `iam_token`    | ✅       | ✅    |
| `metadata`     | ✅       | ✅    |
| `auth_key`     | ✅       | ✅    |
| `access_token` | ❌       | ✅    |
| `anonymous`    | ❌       | ✅    |
| `static`       | ❌       | ✅    |

Requesting a token for an unsupported usage throws
`UnsupportedAuthMethodError` naming the usage, the strategy and the
supported strategies.

`auth.getProvider(usage?)` returns a `TokenProvider`; when a usage is given,
compatibility is validated on every `getToken()` call.

## YDB adapter (`@ycforge/auth/ydb`)

Requires the optional peer `@ydbjs/auth` (>= 6).

```ts
import { createYdbCredentialsProvider } from '@ycforge/auth/ydb';

const credentials = createYdbCredentialsProvider(auth);
// driver usage (ydb-js-sdk): pass `credentials` where a CredentialsProvider
// is expected; its middleware injects the token as `x-ydb-auth-ticket`.

// username/password login needs the YDB endpoint:
const staticCreds = createYdbCredentialsProvider(auth, {
  endpoint: 'grpcs://ydb.serverless.yandexcloud.net:2135',
  secure: true, // default; false for local insecure YDB
});
```

Strategy mapping:

- `static` → `StaticCredentialsProvider` from `@ydbjs/auth`
  (`options.endpoint` required),
- `anonymous` → `AnonymousCredentialsProvider`,
- everything else → a thin `CredentialsProvider` delegating `getToken()` to
  `auth.getToken('ydb')`.

## NestJS module (`@ycforge/auth/nestjs`)

Requires the optional peers `@nestjs/common` (>= 10) and `reflect-metadata`.

```ts
import { Module } from '@nestjs/common';
import {
  InjectAuth,
  YCFORGE_AUTH,
  YcAuthModule,
} from '@ycforge/auth/nestjs';
import type { AuthManager } from '@ycforge/auth';

@Module({
  imports: [
    YcAuthModule.forRoot({
      config: { type: 'metadata' },
      global: true, // optional
    }),
    // or asynchronously:
    // YcAuthModule.forRootAsync({
    //   inject: [ConfigService],
    //   useFactory: (cfg: ConfigService) => cfg.get('auth'),
    // }),
  ],
})
export class AppModule {}

@Injectable()
export class SomeService {
  constructor(@InjectAuth() private readonly auth: AuthManager) {}
}
```

The manager is provided under the `YCFORGE_AUTH` symbol and is also
retrievable via `moduleRef.get(YCFORGE_AUTH)`.

### Example: sharing one `AuthManager` with `@ycforge/ydb-orm`

If you already have `YcAuthModule` registered, you can inject the same
`AuthManager` into the YDB ORM module instead of duplicating credentials.

```ts
import { Module, Inject } from '@nestjs/common';
import { YdbModule } from '@ycforge/ydb-orm';
import { YCFORGE_AUTH, YcAuthModule, InjectAuth } from '@ycforge/auth/nestjs';
import type { AuthManager } from '@ycforge/auth';

@Module({
  imports: [
    YcAuthModule.forRoot({
      config: { type: 'metadata' },
      global: true,
    }),
    YdbModule.forRootAsync({
      useFactory: (auth: AuthManager) => ({
        endpoint: 'grpcs://ydb.serverless.yandexcloud.net:2135',
        database: '/ru-central1/.../...',
        auth, // let ydb-orm wrap it into a CredentialsProvider for YDB
      }),
      inject: [YCFORGE_AUTH],
    }),
  ],
})
export class AppModule {}
```

The ORM will use the injected `auth` manager and request tokens with usage
`'ydb'`. If the configured strategy is incompatible with YDB (e.g. an
`access_token` used where IAM is expected), you get the same behaviour as
passing a custom `CredentialsProvider`.

### Example: sharing one `AuthManager` with `@ycforge/orm-security-providers`

Use the same `AuthManager` for Yandex Cloud security providers. Register the
module once and inject the manager where the provider expects it; the provider
will request tokens with usage `'ycloud'`.

```ts
import { Module } from '@nestjs/common';
import { YandexKmsModule } from '@ycforge/orm-security-providers';
import { YCFORGE_AUTH, YcAuthModule } from '@ycforge/auth/nestjs';
import type { AuthManager } from '@ycforge/auth';

@Module({
  imports: [
    YcAuthModule.forRoot({
      global: true,
      config: authKeyFromFile('./keys/kms-key.json'),
    }),
    YandexKmsModule.forRootAsync({
      useFactory: (auth: AuthManager) => ({
        keyId: process.env.KMS_KEY_ID!,
        auth,
      }),
      inject: [YCFORGE_AUTH],
    }),
  ],
})
export class AppModule {}
```

A single `AuthManager` instance now serves both YDB and YCloud consumers; each
consumer requests the appropriate usage (`'ydb'` or `'ycloud'`).

## Scripts

```bash
yarn build   # tsc → dist/
yarn test    # jest (ESM, ts-jest)
yarn lint    # eslint + prettier
```

## License

MIT
