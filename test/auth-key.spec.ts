import { jest } from '@jest/globals';
import crypto from 'node:crypto';

const mockReadFileSync = jest.fn() as jest.MockedFunction<
  (path: string, encoding: BufferEncoding) => string
>;

jest.unstable_mockModule('node:fs', () => ({
  default: { readFileSync: mockReadFileSync },
  readFileSync: mockReadFileSync,
}));

const {
  AuthError,
  AuthConfigurationError,
  AuthKeyTokenProvider,
  authKeyFromFile,
  IAM_TOKEN_URL,
  TOKEN_EXPIRY_LEEWAY_MS,
} = await import('../src/index.js');

const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
});
const privateKeyPem = privateKey.export({
  type: 'pkcs8',
  format: 'pem',
}) as string;

const CREDENTIALS = {
  keyId: 'aje123',
  serviceAccountId: 'sa-456',
  privateKey: privateKeyPem,
};

const originalFetch = globalThis.fetch;

function jsonResponse(data: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: () => Promise.resolve(data),
    text: () => Promise.resolve(JSON.stringify(data)),
  } as Response;
}

function mockFetch(impl: () => Promise<Response>) {
  globalThis.fetch = jest.fn(impl);
  return globalThis.fetch as jest.MockedFunction<typeof fetch>;
}

afterEach(() => {
  globalThis.fetch = originalFetch;
  jest.clearAllMocks();
});

describe('AuthKeyTokenProvider', () => {
  it('exchanges a PS256 JWT for an IAM token', async () => {
    const expiresAt = new Date(Date.now() + 3600_000).toISOString();
    const fetchMock = mockFetch(() =>
      Promise.resolve(jsonResponse({ iamToken: 'iam-t', expiresAt })),
    );

    const provider = new AuthKeyTokenProvider(CREDENTIALS);
    await expect(provider.getToken()).resolves.toBe('iam-t');

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as unknown as [
      string,
      RequestInit,
    ];
    expect(url).toBe(IAM_TOKEN_URL);
    expect(init.method).toBe('POST');

    const { jwt } = JSON.parse(init.body as string) as { jwt: string };
    const [h, p, s] = jwt.split('.');

    const header = JSON.parse(Buffer.from(h, 'base64url').toString()) as Record<
      string,
      unknown
    >;
    expect(header).toEqual({ alg: 'PS256', typ: 'JWT', kid: 'aje123' });

    const payload = JSON.parse(
      Buffer.from(p, 'base64url').toString(),
    ) as Record<string, unknown>;
    expect(payload.iss).toBe('sa-456');
    expect(payload.sub).toBe('sa-456');
    expect(payload.aud).toBe(IAM_TOKEN_URL);
    expect(payload.exp).toBe((payload.iat as number) + 3600);

    // Verify the PS256 signature against the public key.
    const valid = crypto.verify(
      'sha256',
      Buffer.from(`${h}.${p}`),
      {
        key: publicKey,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
      },
      Buffer.from(s, 'base64url'),
    );
    expect(valid).toBe(true);
  });

  it('signs with RSA-PSS padding (crypto.sign called accordingly)', async () => {
    const signSpy = jest.spyOn(crypto, 'sign');
    mockFetch(() =>
      Promise.resolve(
        jsonResponse({
          iamToken: 't',
          expiresAt: new Date(Date.now() + 3600_000).toISOString(),
        }),
      ),
    );

    const provider = new AuthKeyTokenProvider(CREDENTIALS);
    await provider.getToken();

    expect(signSpy).toHaveBeenCalled();
    const options = signSpy.mock.calls[0][2] as crypto.SignKeyObjectInput;
    expect(options.padding).toBe(crypto.constants.RSA_PKCS1_PSS_PADDING);
    expect(options.saltLength).toBe(crypto.constants.RSA_PSS_SALTLEN_DIGEST);
    signSpy.mockRestore();
  });

  it('caches the token and refreshes after leeway', async () => {
    let now = Date.now();
    const nowSpy = jest.spyOn(Date, 'now').mockImplementation(() => now);
    const expiresAt = new Date(now + 3600_000).toISOString();
    const fetchMock = mockFetch(() =>
      Promise.resolve(jsonResponse({ iamToken: 'iam-t', expiresAt })),
    );

    const provider = new AuthKeyTokenProvider(CREDENTIALS);
    await provider.getToken();
    await provider.getToken();
    expect(fetchMock).toHaveBeenCalledTimes(1);

    now += 3600_000 - TOKEN_EXPIRY_LEEWAY_MS + 1;
    await provider.getToken();
    expect(fetchMock).toHaveBeenCalledTimes(2);
    nowSpy.mockRestore();
  });

  it('single-flights concurrent refreshes', async () => {
    let resolveResponse: (r: Response) => void = () => {};
    const fetchMock = mockFetch(
      () =>
        new Promise<Response>((resolve) => {
          resolveResponse = resolve;
        }),
    );
    const provider = new AuthKeyTokenProvider(CREDENTIALS);

    const p1 = provider.getToken();
    const p2 = provider.getToken();
    resolveResponse(
      jsonResponse({
        iamToken: 'iam-t',
        expiresAt: new Date(Date.now() + 3600_000).toISOString(),
      }),
    );
    await expect(p1).resolves.toBe('iam-t');
    await expect(p2).resolves.toBe('iam-t');
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('retries network errors and drops the cache on failure', async () => {
    jest.useFakeTimers();
    try {
      const okExpires = new Date(Date.now() + 3600_000).toISOString();
      let calls = 0;
      const fetchMock = mockFetch(() => {
        calls++;
        return calls === 1
          ? Promise.resolve(
              jsonResponse({ iamToken: 'first', expiresAt: okExpires }),
            )
          : Promise.reject(new Error('boom'));
      });

      const provider = new AuthKeyTokenProvider(CREDENTIALS);
      await expect(provider.getToken()).resolves.toBe('first');

      const failing = provider.getToken(true);
      const assertion = expect(failing).rejects.toThrow(/boom/);
      await jest.runAllTimersAsync();
      await assertion;
      expect(fetchMock.mock.calls.length).toBe(1 + 5); // initial + 5 attempts

      // Cache cleared: next call hits the network again (and fails).
      const again = provider.getToken();
      const againAssertion = expect(again).rejects.toThrow(/boom/);
      await jest.runAllTimersAsync();
      await againAssertion;
    } finally {
      jest.useRealTimers();
    }
  });

  it('does not retry non-retryable errors (missing iamToken)', async () => {
    jest.useFakeTimers();
    try {
      const fetchMock = mockFetch(() =>
        Promise.resolve(jsonResponse({ iamToken: '' })),
      );
      const provider = new AuthKeyTokenProvider(CREDENTIALS);
      const promise = provider.getToken();
      const assertion = expect(promise).rejects.toThrow(/no iamToken/);
      await jest.runAllTimersAsync();
      await assertion;
      expect(fetchMock).toHaveBeenCalledTimes(1);
    } finally {
      jest.useRealTimers();
    }
  });

  it('does not retry invalid JSON responses', async () => {
    jest.useFakeTimers();
    try {
      const fetchMock = mockFetch(() =>
        Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.reject(new Error('bad json')),
        } as unknown as Response),
      );
      const provider = new AuthKeyTokenProvider(CREDENTIALS);
      const promise = provider.getToken();
      const assertion = expect(promise).rejects.toThrow(/not valid JSON/);
      await jest.runAllTimersAsync();
      await assertion;
      expect(fetchMock).toHaveBeenCalledTimes(1);
    } finally {
      jest.useRealTimers();
    }
  });

  it('does not retry invalid expiresAt values', async () => {
    jest.useFakeTimers();
    try {
      const fetchMock = mockFetch(() =>
        Promise.resolve(jsonResponse({ iamToken: 't', expiresAt: 'junk' })),
      );
      const provider = new AuthKeyTokenProvider(CREDENTIALS);
      const promise = provider.getToken();
      const assertion = expect(promise).rejects.toThrow(AuthError);
      await jest.runAllTimersAsync();
      await assertion;
      expect(fetchMock).toHaveBeenCalledTimes(1);
    } finally {
      jest.useRealTimers();
    }
  });

  it('never leaks the HTTP error body', async () => {
    jest.useFakeTimers();
    try {
      const warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
      mockFetch(() =>
        Promise.resolve({
          ok: false,
          status: 401,
          json: () => Promise.resolve({ secret: 'TOP-SECRET-BODY' }),
          text: () => Promise.resolve('TOP-SECRET-BODY'),
        } as unknown as Response),
      );

      const provider = new AuthKeyTokenProvider(CREDENTIALS);
      const promise = provider.getToken();
      const assertion = expect(promise).rejects.toThrow(/status 401/);
      await jest.runAllTimersAsync();
      await assertion;

      const logged = warnSpy.mock.calls.flat().join(' ');
      expect(logged).not.toContain('TOP-SECRET-BODY');
      warnSpy.mockRestore();
    } finally {
      jest.useRealTimers();
    }
  });

  it('falls back to default TTL when expiresAt is missing', async () => {
    const warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
    mockFetch(() => Promise.resolve(jsonResponse({ iamToken: 't' })));

    const provider = new AuthKeyTokenProvider(CREDENTIALS);
    await expect(provider.getToken()).resolves.toBe('t');
    expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('expiresAt'));
    warnSpy.mockRestore();
  });

  it('validates fetchTimeoutMs', () => {
    expect(
      () => new AuthKeyTokenProvider(CREDENTIALS, { fetchTimeoutMs: 0 }),
    ).toThrow(AuthConfigurationError);
  });
});

describe('authKeyFromFile', () => {
  it('parses a valid authorized key file', () => {
    mockReadFileSync.mockReturnValue(
      JSON.stringify({
        id: 'aje123',
        service_account_id: 'sa-456',
        private_key: privateKeyPem,
      }),
    );

    const config = authKeyFromFile('/tmp/authorized_key.json');
    expect(config).toEqual({
      type: 'auth_key',
      keyId: 'aje123',
      serviceAccountId: 'sa-456',
      privateKey: privateKeyPem,
    });
  });

  it('rejects files with missing fields', () => {
    mockReadFileSync.mockReturnValue(JSON.stringify({ id: 'aje123' }));
    expect(() => authKeyFromFile('/tmp/key.json')).toThrow(
      AuthConfigurationError,
    );
    expect(() => authKeyFromFile('/tmp/key.json')).toThrow(
      /id, service_account_id, private_key/,
    );
  });

  it('rejects files with an unparseable private key', () => {
    mockReadFileSync.mockReturnValue(
      JSON.stringify({
        id: 'aje123',
        service_account_id: 'sa-456',
        private_key: 'not-a-key',
      }),
    );
    expect(() => authKeyFromFile('/tmp/key.json')).toThrow(
      /not a parseable key/,
    );
  });
});
