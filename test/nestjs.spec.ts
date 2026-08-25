import "reflect-metadata";
import { Injectable, Module } from "@nestjs/common";
import { Test } from "@nestjs/testing";

import { AuthManager, createAuth } from "../src/index.js";
import { InjectAuth, YCFORGE_AUTH, YcAuthModule } from "../src/nestjs/index.js";

describe("YcAuthModule", () => {
  it("forRoot provides an AuthManager via YCFORGE_AUTH", async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [
        YcAuthModule.forRoot({ config: { type: "iam_token", token: "tok" } }),
      ],
    }).compile();

    const auth = moduleRef.get<AuthManager>(YCFORGE_AUTH);
    expect(auth).toBeInstanceOf(AuthManager);
    await expect(auth.getToken("ycloud")).resolves.toBe("tok");
    await moduleRef.close();
  });

  it("InjectAuth injects the manager into a provider", async () => {
    @Injectable()
    class Consumer {
      constructor(@InjectAuth() public readonly auth: AuthManager) {}
    }

    @Module({
      imports: [
        YcAuthModule.forRoot({
          config: { type: "access_token", token: "at" },
        }),
      ],
      providers: [Consumer],
    })
    class TestModule {}

    const moduleRef = await Test.createTestingModule({
      imports: [TestModule],
    }).compile();

    const consumer = moduleRef.get(Consumer);
    expect(consumer.auth).toBeInstanceOf(AuthManager);
    await expect(consumer.auth.getToken("ydb")).resolves.toBe("at");
    await moduleRef.close();
  });

  it("forRootAsync resolves config from a factory with injected deps", async () => {
    const CONFIG_TOKEN = Symbol("CONFIG_TOKEN");

    const moduleRef = await Test.createTestingModule({
      imports: [
        YcAuthModule.forRootAsync({
          imports: [
            {
              module: class ConfigModule {},
              providers: [{ provide: CONFIG_TOKEN, useValue: "async-token" }],
              exports: [CONFIG_TOKEN],
            },
          ],
          inject: [CONFIG_TOKEN],
          useFactory: (token: string) => ({
            type: "iam_token",
            token,
          }),
        }),
      ],
    }).compile();

    const auth = moduleRef.get<AuthManager>(YCFORGE_AUTH);
    await expect(auth.getToken("ycloud")).resolves.toBe("async-token");
    await moduleRef.close();
  });

  it("global: true makes the manager available without imports", async () => {
    @Injectable()
    class GlobalConsumer {
      constructor(@InjectAuth() public readonly auth: AuthManager) {}
    }

    @Module({ providers: [GlobalConsumer] })
    class OtherModule {}

    const moduleRef = await Test.createTestingModule({
      imports: [
        YcAuthModule.forRoot({
          config: { type: "iam_token", token: "global-tok" },
          global: true,
        }),
        OtherModule,
      ],
    }).compile();

    const consumer = moduleRef.get(GlobalConsumer);
    expect(consumer.auth).toBeInstanceOf(AuthManager);
    await expect(consumer.auth.getToken("ycloud")).resolves.toBe("global-tok");
    await moduleRef.close();
  });

  it("keeps an equivalent manager constructible without NestJS", async () => {
    const auth = createAuth({ type: "anonymous" });
    await expect(auth.getToken("ydb")).resolves.toBe("");
  });
});
