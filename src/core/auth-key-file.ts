import fs from 'node:fs';
import crypto from 'node:crypto';

import { AuthConfigurationError } from './errors.js';
import type { AuthStrategyConfig } from './types.js';

/**
 * Reads a service account authorized key JSON file
 * ({ id, service_account_id, private_key }) and returns an `auth_key`
 * strategy config. The private key is validated eagerly so a broken key
 * fails at startup, not at the first token exchange.
 */
export function authKeyFromFile(
  path: string,
): Extract<AuthStrategyConfig, { type: 'auth_key' }> {
  const raw = fs.readFileSync(path, 'utf-8');
  const json = JSON.parse(raw) as Record<string, unknown>;

  if (!json.id || !json.service_account_id || !json.private_key) {
    throw new AuthConfigurationError(
      `Invalid authorized key file at ${path}. Expected fields: id, service_account_id, private_key`,
    );
  }

  try {
    crypto.createPrivateKey(json.private_key as string);
  } catch {
    throw new AuthConfigurationError(
      `Invalid authorized key file at ${path}: private_key is not a parseable key`,
    );
  }

  return {
    type: 'auth_key',
    keyId: json.id as string,
    serviceAccountId: json.service_account_id as string,
    privateKey: json.private_key as string,
  };
}
