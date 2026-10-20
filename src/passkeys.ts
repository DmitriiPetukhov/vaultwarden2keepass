import { createPrivateKey } from 'node:crypto';
import type { KdbxEntry } from 'kdbxweb';
import type { Fido2Credential } from './bitwardenCliTypes';
import { protect } from './fieldMappingsUtil';

function decodeBase64Url(value: string): Buffer {
  if (!/^[A-Za-z0-9_-]+={0,2}$/.test(value)) {
    throw new Error('Invalid base64url value');
  }

  const unpadded = value.replace(/=+$/, '');
  const padding = value.length - unpadded.length;
  const expectedPadding = (4 - (unpadded.length % 4)) % 4;
  if (unpadded.length % 4 === 1 || (padding > 0 && padding !== expectedPadding)) {
    throw new Error('Invalid base64url encoding');
  }

  const bytes = Buffer.from(value, 'base64url');
  if (bytes.length === 0 || bytes.toString('base64url') !== unpadded) {
    throw new Error('Invalid base64url encoding');
  }

  return bytes;
}

export function normalizeCredentialId(input: string): string {
  const value = input.trim();
  let bytes: Buffer;

  if (/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(value)) {
    bytes = Buffer.from(value.replace(/-/g, ''), 'hex');
  } else if (value.startsWith('b64.')) {
    bytes = decodeBase64Url(value.slice(4));
  } else if (/^(?:[a-f0-9]{2})+$/i.test(value)) {
    bytes = Buffer.from(value, 'hex');
  } else {
    bytes = decodeBase64Url(value);
  }

  if (bytes.length === 0 || bytes.every((byte) => byte === 0)) {
    throw new Error('Invalid passkey credential ID');
  }

  return bytes.toString('base64url');
}

export function addPasskeyToEntry(
  entry: KdbxEntry,
  credential: Fido2Credential,
  fallbackUsername = '',
): void {
  if (entry.fields.has('KPEX_PASSKEY_CREDENTIAL_ID')) {
    throw new Error('Entry already contains a passkey');
  }

  if (!credential.credentialId || !credential.keyValue || !credential.rpId?.trim()) {
    throw new Error('Incomplete passkey data');
  }

  if (credential.keyAlgorithm !== 'ECDSA' || credential.keyCurve !== 'P-256') {
    throw new Error('Unsupported passkey algorithm or curve');
  }

  const credentialId = normalizeCredentialId(credential.credentialId);
  const der = decodeBase64Url(credential.keyValue);

  let pem: string;
  try {
    const key = createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
    if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1') {
      throw new Error('Unexpected passkey private-key type');
    }
    pem = key.export({ format: 'pem', type: 'pkcs8' }).toString();
  } catch {
    throw new Error('Invalid passkey private key; expected PKCS#8 EC P-256');
  }

  const userHandle = credential.userHandle
    ? decodeBase64Url(credential.userHandle).toString('base64url')
    : '';
  entry.fields.set('KPEX_PASSKEY_CREDENTIAL_ID', protect(credentialId));
  entry.fields.set('KPEX_PASSKEY_PRIVATE_KEY_PEM', protect(pem));
  entry.fields.set('KPEX_PASSKEY_RELYING_PARTY', credential.rpId);
  entry.fields.set('KPEX_PASSKEY_USER_HANDLE', protect(userHandle));
  entry.fields.set('KPEX_PASSKEY_USERNAME', credential.userName ?? fallbackUsername);
  entry.fields.set('KPEX_PASSKEY_FLAG_BE', '1');
  entry.fields.set('KPEX_PASSKEY_FLAG_BS', '1');

  if (!entry.tags.includes('Passkey')) entry.tags.push('Passkey');
}
