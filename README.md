# @ycforge/auth

Общая логика аутентификации для API Яндекс Облака и YDB, выделенная из
`@ycforge/ydb-orm` и `@ycforge/yandex-kms-orm-provider`.

- Нулевое количество runtime-зависимостей в ядре (только Node.js builtins + глобальный `fetch`).
- Кэширование токенов с запасом 60 секунд и single-flight обновлением.
- Встроенный retry с экспоненциальным бэкоффом (5 попыток, базовая задержка 100 мс, множитель 10).
- Capability-матрица: каждый запрос токена проверяется на совместимость с целевым использованием.
- Опциональные адаптеры: `@ydbjs/auth` (драйвер YDB) и NestJS.

Требуется Node.js >= 22 (ESM).

## Установка

```bash
yarn add @ycforge/auth
# опционально, для YDB-адаптера:
yarn add @ydbjs/auth
# опционально, для NestJS-модуля:
yarn add @nestjs/common reflect-metadata
```

## Быстрый старт

```ts
import { createAuth, YCLOUD_AUTH_USAGE } from '@ycforge/auth';

const auth = createAuth({ type: 'metadata' });
const token = await auth.getToken(YCLOUD_AUTH_USAGE);
```

## Стратегии

### `iam_token` — статический IAM-токен

```ts
const auth = createAuth({
  type: 'iam_token',
  token: process.env.IAM_TOKEN!,
  // опционально: после наступления этого момента getToken() будет бросать ошибку
  // вместо возврата заведомо протухшего токена (Date, ISO-строка или unix s/ms)
  expiresAt: '2026-09-01T00:00:00Z',
});
```

### `metadata` — сервис метаданных ВМ

```ts
const auth = createAuth({
  type: 'metadata',
  // значения по умолчанию:
  endpoint:
    'http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token',
  flavor: 'Google',
});
```

### `auth_key` — авторизованный ключ сервисного аккаунта

Подписывает JWT с алгоритмом PS256 и обменивает его на IAM-токен по адресу
`https://iam.api.cloud.yandex.net/iam/v1/tokens` (таймаут 10 с на запрос,
retry с бэкоффом, тела HTTP-ошибок никогда не логируются).

```ts
import { createAuth, authKeyFromFile } from '@ycforge/auth';

const auth = createAuth(authKeyFromFile('./authorized_key.json'));
// или inline:
const auth2 = createAuth({
  type: 'auth_key',
  keyId: 'aje...',
  serviceAccountId: 'sa-...',
  privateKey: process.env.PRIVATE_KEY!,
});
```

### `access_token` / `anonymous` / `static` (только YDB)

```ts
createAuth({ type: 'access_token', token: '...' });
createAuth({ type: 'anonymous' }); // пустой токен
createAuth({ type: 'static', username: 'user', password: 'pass' });
```

Стратегия `static` (username/password) не может получить токен без YDB gRPC
эндпоинта: в ядре её `getToken()` бросает ошибку с подсказкой использовать
адаптер `@ycforge/auth/ydb`, который делегирует вызовы
`StaticCredentialsProvider` из `@ydbjs/auth`.

## Capability-матрица

| Стратегия      | `ycloud` | `ydb` |
| -------------- | -------- | ----- |
| `iam_token`    | ✅       | ✅    |
| `metadata`     | ✅       | ✅    |
| `auth_key`     | ✅       | ✅    |
| `access_token` | ❌       | ✅    |
| `anonymous`    | ❌       | ✅    |
| `static`       | ❌       | ✅    |

Запрос токена для неподдерживаемого использования бросает
`UnsupportedAuthMethodError`, указывая usage, стратегию и список поддерживаемых
стратегий.

`auth.getProvider(usage?)` возвращает `TokenProvider`; если usage передан,
совместимость проверяется на каждом вызове `getToken()`.

## YDB-адаптер (`@ycforge/auth/ydb`)

Требует опционального peer-зависимости `@ydbjs/auth` (>= 6).

### Зачем нужен адаптер

`@ydbjs/auth` (слой аутентификации YDB JS SDK) ожидает объект
`CredentialsProvider`. Этот объект должен реализовывать `getToken()` и уже
уметь подставлять возвращаемое значение в gRPC-метаданные как
`x-ydb-auth-ticket`. Адаптер `@ycforge/auth/ydb` превращает ваш `AuthManager`
именно в такой `CredentialsProvider`, поэтому одна и та же конфигурация
аутентификации может использоваться и для REST API Яндекс Облака, и для YDB.

### Зачем нужны `endpoint` / `secure` / `channelOptions`?

Большинству стратегий YDB-эндпоинт **не нужен**. Адаптер требует его только
для стратегии `static` (username/password), потому что
`StaticCredentialsProvider` из `@ydbjs/auth` выполняет gRPC-вызов `Login` к
YDB-эндпоинту для обмена учётных данных на auth ticket.

Для `iam_token`, `metadata`, `auth_key`, `access_token` и `anonymous`
параметры `endpoint`, `secure` и `channelOptions` игнорируются — адаптер просто
вызывает `auth.getToken(usage)` и позволяет `@ycforge/auth` заниматься
кэшированием и обновлением токена.

### Примеры использования

Первый аргумент адаптера — `AuthManager`, второй обязательный аргумент —
`usage` (`'ydb'` или `'ycloud'`), третий опциональный — настройки
`YdbCredentialsAdapterOptions`.

```ts
import { createAuth, authKeyFromFile, YDB_AUTH_USAGE } from '@ycforge/auth';
import { createYdbCredentialsProvider } from '@ycforge/auth/ydb';

// Стратегии, которым НЕ нужен endpoint:
const authKey = createAuth(authKeyFromFile('./authorized_key.json'));
const iam = createAuth({ type: 'iam_token', token: process.env.IAM_TOKEN! });
const meta = createAuth({ type: 'metadata' });
const anon = createAuth({ type: 'anonymous' });

const creds = createYdbCredentialsProvider(authKey, YDB_AUTH_USAGE);
// Передайте `creds` в Driver ydb-js-sdk там, где ожидается CredentialsProvider.

// Для логина по логину/паролю endpoint НУЖЕН:
const staticAuth = createAuth({
  type: 'static',
  username: 'user',
  password: 'pass',
});
const staticCreds = createYdbCredentialsProvider(staticAuth, YDB_AUTH_USAGE, {
  endpoint: 'grpcs://ydb.serverless.yandexcloud.net:2135',
  secure: true, // по умолчанию; установите false для локального незащищённого YDB (grpc://)
});
```

Стратегия `static` работает только с `usage === 'ydb'`. При попытке передать
`'ycloud'` адаптер бросит `AuthConfigurationError`.

### Маппинг стратегий

| Стратегия       | Что возвращает адаптер                                       | Нужен `endpoint` |
| --------------- | ------------------------------------------------------------ | ---------------- |
| `static`        | `StaticCredentialsProvider` из `@ydbjs/auth`                 | да               |
| `anonymous`     | `AnonymousCredentialsProvider` из `@ydbjs/auth`              | нет              |
| всё остальное   | Тонкий `CredentialsProvider`, делегирующий `auth.getToken(usage)` | нет              |

## NestJS-модуль (`@ycforge/auth/nestjs`)

Требует опциональных peer-зависимостей `@nestjs/common` (>= 10) и
`reflect-metadata`.

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
      global: true, // опционально
    }),
    // или асинхронно:
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

Менеджер предоставляется под символом `YCFORGE_AUTH` и также доступен через
`moduleRef.get(YCFORGE_AUTH)`.

### Пример: использование одного `AuthManager` с `@ycforge/ydb-orm`

Если у вас уже зарегистрирован `YcAuthModule`, можно внедрить тот же
`AuthManager` в модуль YDB ORM вместо дублирования учётных данных.

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
        auth, // ydb-orm сам обернёт его в CredentialsProvider для YDB
      }),
      inject: [YCFORGE_AUTH],
    }),
  ],
})
export class AppModule {}
```

ORM будет использовать внедрённый `auth`-менеджер и запрашивать токены с
usage `'ydb'`. Если настроенная стратегия несовместима с YDB (например,
`access_token` там, где ожидается IAM), поведение будет таким же, как при
передаче произвольного `CredentialsProvider`.

### Пример: использование одного `AuthManager` с `@ycforge/orm-security-providers`

Используйте тот же `AuthManager` для security-провайдеров Яндекс Облака.
Зарегистрируйте модуль один раз и внедряйте менеджер туда, где его ожидает
провайдер; провайдер будет запрашивать токены с usage `'ycloud'`.

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

Один экземпляр `AuthManager` теперь обслуживает и YDB, и YCloud потребителей;
каждый потребитель запрашивает нужный usage (`'ydb'` или `'ycloud'`).

## Скрипты

```bash
yarn build   # tsc → dist/
yarn test    # jest (ESM, ts-jest)
yarn lint    # eslint + prettier
```

## Лицензия

MIT
