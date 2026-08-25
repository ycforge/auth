/** Marker for errors that must not be retried (deterministic failures). */
const NON_RETRYABLE = Symbol("YcForgeAuthNonRetryableError");

export function markNonRetryable<E extends Error>(err: E): E {
  (err as unknown as { [NON_RETRYABLE]?: boolean })[NON_RETRYABLE] = true;
  return err;
}

export function isNonRetryable(err: unknown): boolean {
  return (
    err instanceof Error &&
    (err as { [NON_RETRYABLE]?: boolean })[NON_RETRYABLE] === true
  );
}

export interface RetryOptions {
  /** Total attempt budget including the first try (default: 5). */
  attempts?: number;
  /** Base delay in ms; each retry waits base * factor^attempt (default: 100). */
  baseDelayMs?: number;
  /** Backoff multiplier (default: 10). */
  factor?: number;
  /** Aborts waiting between attempts. */
  signal?: AbortSignal;
  /** Decide whether an error is worth retrying (default: everything retryable). */
  isRetryable?: (err: unknown) => boolean;
  /** Called before sleeping between attempts. */
  onRetry?: (attempt: number, err: unknown, delayMs: number) => void;
}

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    const onAbort = () => {
      clearTimeout(timer);
      reject(
        signal?.reason instanceof Error ? signal.reason : new Error("Aborted"),
      );
    };
    if (signal?.aborted) {
      onAbort();
      return;
    }
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

/** Minimal exponential backoff retry: no external dependencies. */
export async function retry<T>(
  fn: (signal?: AbortSignal) => Promise<T>,
  options: RetryOptions = {},
): Promise<T> {
  const attempts = options.attempts ?? 5;
  const baseDelayMs = options.baseDelayMs ?? 100;
  const factor = options.factor ?? 10;
  const isRetryable =
    options.isRetryable ??
    ((err: unknown) => err instanceof Error && !isNonRetryable(err));

  let lastError: unknown;
  for (let attempt = 1; attempt <= attempts; attempt++) {
    options.signal?.throwIfAborted();
    try {
      return await fn(options.signal);
    } catch (err) {
      lastError = err;
      if (attempt >= attempts || !isRetryable(err)) {
        throw err;
      }
      const delayMs = baseDelayMs * Math.pow(factor, attempt - 1);
      options.onRetry?.(attempt, err, delayMs);
      await sleep(delayMs, options.signal);
    }
  }
  throw lastError;
}
