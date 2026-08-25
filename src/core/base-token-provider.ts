import { AuthError } from "./errors.js";
import type { TokenProvider } from "./types.js";

/**
 * Leeway before token expiry: without it a token could expire between
 * the cache check and the actual API request.
 */
export const TOKEN_EXPIRY_LEEWAY_MS = 60_000;

/** A cached token; expiresAt = null means "lifetime unknown / never expires". */
export interface CachedToken {
  value: string;
  expiresAt: Date | null;
}

export function isCacheValid(token: CachedToken, now = Date.now()): boolean {
  if (token.expiresAt === null) return true;
  return token.expiresAt.getTime() - TOKEN_EXPIRY_LEEWAY_MS > now;
}

/**
 * Base class for token providers with caching (60s leeway) and
 * single-flight refresh (concurrent getToken() calls share one request).
 * On a failed refresh the cache is dropped so a stale token is never served.
 */
export abstract class BaseTokenProvider implements TokenProvider {
  #inflight: Promise<string> | null = null;
  #cache: CachedToken | null = null;

  protected get cache(): CachedToken | null {
    return this.#cache;
  }

  protected set cache(token: CachedToken | null) {
    this.#cache = token;
  }

  /** Fetch a fresh token. Called at most once at a time. */
  protected abstract fetchToken(signal?: AbortSignal): Promise<CachedToken>;

  async getToken(force?: boolean, signal?: AbortSignal): Promise<string> {
    if (!force && this.#cache && isCacheValid(this.#cache)) {
      return this.#cache.value;
    }

    if (this.#inflight) {
      return this.#inflight;
    }

    this.#inflight = this.fetchToken(signal)
      .then((token) => {
        this.#cache = token;
        return token.value;
      })
      .catch((err) => {
        // Refresh failed — never serve a stale token from the cache.
        this.#cache = null;
        throw err;
      })
      .finally(() => {
        this.#inflight = null;
      });

    return this.#inflight;
  }
}

/**
 * Historical threshold for numeric timestamps: values <= threshold are
 * treated as unix seconds, larger ones as milliseconds.
 * Current unix time is ~1.7e9, milliseconds ~1.7e12.
 */
const SECONDS_TIMESTAMP_THRESHOLD = 100_000_000_000;

/**
 * Parses a timestamp (Date, ISO string, unix seconds/ms) into a Date.
 * Returns null when the value is absent. Invalid values throw — the cache
 * must never degrade to "expires never" silently.
 */
export function parseTimestamp(ts: unknown): Date | null {
  if (ts === undefined || ts === null || ts === "") return null;

  let date: Date;
  if (ts instanceof Date) {
    date = new Date(ts.getTime());
  } else if (typeof ts === "number") {
    if (!Number.isFinite(ts) || ts < 0) {
      throw new AuthError(`Invalid numeric timestamp: ${String(ts)}`);
    }
    date = new Date(ts <= SECONDS_TIMESTAMP_THRESHOLD ? ts * 1000 : ts);
  } else if (typeof ts === "string") {
    date = new Date(ts);
  } else {
    throw new AuthError(`Invalid timestamp: unexpected type ${typeof ts}`);
  }

  if (Number.isNaN(date.getTime())) {
    throw new AuthError(
      `Invalid timestamp: ${
        typeof ts === "string" || typeof ts === "number"
          ? String(ts)
          : typeof ts
      }`,
    );
  }
  return date;
}
