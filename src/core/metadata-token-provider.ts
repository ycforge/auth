import { AuthError } from './errors.js';
import { retry } from './retry.js';
import { BaseTokenProvider, type CachedToken } from './base-token-provider.js';

const DEFAULT_METADATA_ENDPOINT =
  'http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token';

const DEFAULT_METADATA_FLAVOR = 'Google';

/** Default TTL when the metadata response omits expires_in (seconds). */
const DEFAULT_EXPIRES_IN_SEC = 3600;

interface MetadataTokenResponse {
  access_token?: string;
  expires_in?: number;
}

export interface MetadataTokenProviderOptions {
  endpoint?: string;
  flavor?: string;
}

/**
 * Fetches an IAM token from the Yandex Cloud VM metadata service
 * (available on Compute Cloud instances and in serverless runtimes).
 */
export class MetadataTokenProvider extends BaseTokenProvider {
  #endpoint: string;
  #flavor: string;

  constructor(options: MetadataTokenProviderOptions = {}) {
    super();
    this.#endpoint = options.endpoint ?? DEFAULT_METADATA_ENDPOINT;
    this.#flavor = options.flavor ?? DEFAULT_METADATA_FLAVOR;
  }

  protected async fetchToken(signal?: AbortSignal): Promise<CachedToken> {
    return retry(
      async (attemptSignal) => {
        let response: Response;
        try {
          response = await fetch(this.#endpoint, {
            headers: { 'Metadata-Flavor': this.#flavor },
            signal: attemptSignal,
          });
        } catch (err) {
          throw new AuthError(
            `Metadata token request failed: ${
              err instanceof Error ? err.message : String(err)
            }`,
            { cause: err },
          );
        }

        if (!response.ok) {
          // Never read/log the body: it may contain sensitive content.
          throw new AuthError(
            `Metadata token request failed with status ${response.status}`,
          );
        }

        const data = (await response.json()) as MetadataTokenResponse;
        if (typeof data.access_token !== 'string' || data.access_token === '') {
          throw new AuthError('No access_token in metadata response');
        }

        const expiresIn = data.expires_in ?? DEFAULT_EXPIRES_IN_SEC;
        return {
          value: data.access_token,
          expiresAt: new Date(Date.now() + expiresIn * 1000),
        };
      },
      {
        signal,
        onRetry: (attempt, err, delayMs) => {
          console.warn(
            `[ycforge-auth] Metadata token fetch attempt ${attempt} failed ` +
              `(${err instanceof Error ? err.message : String(err)}), ` +
              `retrying in ${delayMs} ms`,
          );
        },
      },
    );
  }
}
