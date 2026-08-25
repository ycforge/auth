import {
  Inject,
  Module,
  type DynamicModule,
  type InjectionToken,
  type ModuleMetadata,
  type OptionalFactoryDependency,
  type Provider,
} from "@nestjs/common";

import { createAuth, type AuthManagerConfig } from "../core/manager.js";

/** DI token for the AuthManager provided by YcAuthModule. */
export const YCFORGE_AUTH = Symbol("YCFORGE_AUTH");

export interface YcAuthModuleOptions {
  /** Auth manager configuration (single config or named configs). */
  config: AuthManagerConfig;
  /** Register the module as global (default: false). */
  global?: boolean;
}

export interface YcAuthModuleAsyncOptions {
  useFactory: (
    ...args: any[]
  ) => AuthManagerConfig | Promise<AuthManagerConfig>;
  inject?: Array<InjectionToken | OptionalFactoryDependency>;
  imports?: ModuleMetadata["imports"];
  /** Register the module as global (default: false). */
  global?: boolean;
}

/**
 * NestJS module wiring an AuthManager into DI.
 *
 * ```ts
 * @Module({ imports: [YcAuthModule.forRoot({ config: { type: 'metadata' } })] })
 * export class AppModule {}
 *
 * constructor(@InjectAuth() private readonly auth: AuthManager) {}
 * ```
 */
@Module({})
export class YcAuthModule {
  static forRoot(options: YcAuthModuleOptions): DynamicModule {
    const provider: Provider = {
      provide: YCFORGE_AUTH,
      useValue: createAuth(options.config),
    };
    return {
      module: YcAuthModule,
      global: options.global ?? false,
      providers: [provider],
      exports: [YCFORGE_AUTH],
    };
  }

  static forRootAsync(options: YcAuthModuleAsyncOptions): DynamicModule {
    const provider: Provider = {
      provide: YCFORGE_AUTH,
      useFactory: async (...args: any[]) =>
        createAuth(await options.useFactory(...args)),
      inject: options.inject ?? [],
    };
    return {
      module: YcAuthModule,
      global: options.global ?? false,
      imports: options.imports ?? [],
      providers: [provider],
      exports: [YCFORGE_AUTH],
    };
  }
}

/** Parameter decorator injecting the AuthManager (wraps @Inject(YCFORGE_AUTH)). */
export function InjectAuth(): ParameterDecorator {
  return Inject(YCFORGE_AUTH);
}
