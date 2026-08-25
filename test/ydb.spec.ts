import { jest } from '@jest/globals';

import {
  AuthConfigurationError,
  UnsupportedAuthMethodError,
  createAuth,
} from '../src/index.js';
import { createYdbCredentialsProvider } from '../src/ydb/index.js';

const originalFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = originalFetch;
  jest.restoreAllMocks();
});

describe('createYdbCredentialsProvider', () => {
  it('delegates getToken to the manager with usage "ydb"', async () => {
    const auth = createAuth({ type: 'iam_token', token: 'iam-tok' });
    const provider = createYdbCredentialsProvider(auth);

    await expect(provider.getToken()).resolves.toBe('iam-tok');
    expect(typeof provider.middleware).toBe('function');
  });

  it('passes force and signal through to the manager', async () => {
    const auth = createAuth({ type: 'iam_token', token: 'iam-tok' });
    const provider = createYdbCredentialsProvider(auth);
    const signal = new AbortController().signal;
    await expect(provider.getToken(true, signal)).resolves.toBe('iam-tok');
  });

  it('returns AnonymousCredentialsProvider for the anonymous strategy', async () => {
    const { AnonymousCredentialsProvider } =
      await import('@ydbjs/auth/anonymous');
    const auth = createAuth({ type: 'anonymous' });
    const provider = createYdbCredentialsProvider(auth);
    expect(provider).toBeInstanceOf(AnonymousCredentialsProvider);
    await expect(provider.getToken()).resolves.toBe('');
  });

  it('returns StaticCredentialsProvider for the static strategy (endpoint required)', async () => {
    const { StaticCredentialsProvider } = await import('@ydbjs/auth/static');
    const auth = createAuth({
      type: 'static',
      username: 'user',
      password: 'pass',
    });
    const provider = createYdbCredentialsProvider(auth, {
      endpoint: 'grpc://localhost:2136',
      secure: false,
    });
    expect(provider).toBeInstanceOf(StaticCredentialsProvider);
  });

  it('static strategy without endpoint throws a clear error', () => {
    const auth = createAuth({
      type: 'static',
      username: 'user',
      password: 'pass',
    });
    expect(() => createYdbCredentialsProvider(auth)).toThrow(
      AuthConfigurationError,
    );
    expect(() => createYdbCredentialsProvider(auth)).toThrow(/endpoint/);
  });

  it('propagates UnsupportedAuthMethodError for ydb-unsupported combos', async () => {
    const auth = createAuth({ type: 'access_token', token: 'at' });
    const provider = createYdbCredentialsProvider(auth);
    // sanity: ydb usage is fine
    await expect(provider.getToken()).resolves.toBe('at');
    // the same manager rejects ycloud
    await expect(auth.getToken('ycloud')).rejects.toThrow(
      UnsupportedAuthMethodError,
    );
  });
});
