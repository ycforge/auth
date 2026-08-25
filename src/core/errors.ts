/** Base class for all errors thrown by @ycforge/auth. */
export class AuthError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = new.target.name;
  }
}

/** The auth configuration itself is invalid (missing fields, unknown config name, etc.). */
export class AuthConfigurationError extends AuthError {}

/** The selected strategy is not supported for the requested usage. */
export class UnsupportedAuthMethodError extends AuthError {
  readonly usage: string;
  readonly strategyType: string;
  readonly supported: readonly string[];

  constructor(
    usage: string,
    strategyType: string,
    supported: readonly string[],
  ) {
    super(
      `Auth strategy "${strategyType}" is not supported for usage "${usage}". ` +
        `Supported strategies for "${usage}": ${supported.join(", ")}`,
    );
    this.usage = usage;
    this.strategyType = strategyType;
    this.supported = supported;
  }
}
