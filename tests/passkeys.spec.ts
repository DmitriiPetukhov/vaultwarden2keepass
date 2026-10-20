import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import type { Fido2Credential } from '../src/bitwardenCliTypes';
import { addPasskeyToEntry, normalizeCredentialId } from '../src/passkeys';
import { Credentials, Kdbx, ProtectedValue } from '../src/kdbxweb';

function createEntry() {
  const db = Kdbx.create(new Credentials(null), 'Passkey test');
  db.createDefaultGroup();
  return db.createEntry(db.getDefaultGroup());
}

function createCredential(overrides: Partial<Fido2Credential> = {}): Fido2Credential {
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return {
    credentialId: 'a2e10494-af23-400c-8146-23234e1830ed',
    keyAlgorithm: 'ECDSA',
    keyCurve: 'P-256',
    keyValue: privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64url'),
    rpId: 'example.com',
    userHandle: 'AQID',
    userName: 'alice',
    ...overrides,
  };
}

describe('normalizeCredentialId', () => {
  it('converts a UUID into base64url credential bytes', () => {
    expect(normalizeCredentialId('a2e10494-af23-400c-8146-23234e1830ed')).toBe(
      'ouEElK8jQAyBRiMjThgw7Q',
    );
  });

  it.each([
    ['b64.AQID', 'AQID'],
    ['010203', 'AQID'],
    ['AQID', 'AQID'],
  ])('normalizes %s', (input, expected) => {
    expect(normalizeCredentialId(input)).toBe(expected);
  });

  it.each(['', '0', '%%%', 'b64.=', '00000000-0000-0000-0000-000000000000'])(
    'rejects invalid credential ID %s',
    (input) => {
      expect(() => normalizeCredentialId(input)).toThrow();
    },
  );
});

describe('addPasskeyToEntry', () => {
  it('adds protected KeePassXC passkey values and plain metadata', () => {
    const entry = createEntry();
    entry.tags.push('Login');
    const credential = createCredential();

    addPasskeyToEntry(entry, credential, 'fallback');

    const credentialId = entry.fields.get('KPEX_PASSKEY_CREDENTIAL_ID');
    const privateKey = entry.fields.get('KPEX_PASSKEY_PRIVATE_KEY_PEM');
    const userHandle = entry.fields.get('KPEX_PASSKEY_USER_HANDLE');
    expect(credentialId).toBeInstanceOf(ProtectedValue);
    expect(privateKey).toBeInstanceOf(ProtectedValue);
    expect(userHandle).toBeInstanceOf(ProtectedValue);
    expect((credentialId as InstanceType<typeof ProtectedValue>).getText()).toBe(
      'ouEElK8jQAyBRiMjThgw7Q',
    );
    expect((privateKey as InstanceType<typeof ProtectedValue>).getText()).toMatch(
      /^-----BEGIN PRIVATE KEY-----[\s\S]+-----END PRIVATE KEY-----\n$/,
    );
    expect((userHandle as InstanceType<typeof ProtectedValue>).getText()).toBe('AQID');
    expect(entry.fields.get('KPEX_PASSKEY_RELYING_PARTY')).toBe('example.com');
    expect(entry.fields.get('KPEX_PASSKEY_USERNAME')).toBe('alice');
    expect(entry.fields.get('KPEX_PASSKEY_FLAG_BE')).toBe('1');
    expect(entry.fields.get('KPEX_PASSKEY_FLAG_BS')).toBe('1');
    expect(entry.tags).toEqual(['Login', 'Passkey']);
  });

  it('round-trips the passkey fields through a KDBX save and load', async () => {
    const password = 'test-password';
    const db = Kdbx.create(
      new Credentials(ProtectedValue.fromString(password)),
      'Passkey round-trip',
    );
    db.createDefaultGroup();
    const entry = db.createEntry(db.getDefaultGroup());
    addPasskeyToEntry(entry, createCredential(), '');

    const saved = await db.save();
    const loaded = await Kdbx.load(saved, new Credentials(ProtectedValue.fromString(password)));
    const [loadedEntry] = [...loaded.getDefaultGroup().allEntries()];

    for (const fieldName of [
      'KPEX_PASSKEY_CREDENTIAL_ID',
      'KPEX_PASSKEY_PRIVATE_KEY_PEM',
      'KPEX_PASSKEY_USER_HANDLE',
    ]) {
      expect(loadedEntry.fields.get(fieldName)).toBeInstanceOf(ProtectedValue);
    }
    expect(
      (
        loadedEntry.fields.get('KPEX_PASSKEY_CREDENTIAL_ID') as InstanceType<typeof ProtectedValue>
      ).getText(),
    ).toBe('ouEElK8jQAyBRiMjThgw7Q');
    expect(loadedEntry.fields.get('KPEX_PASSKEY_RELYING_PARTY')).toBe('example.com');
    expect(loadedEntry.tags).toContain('Passkey');
  });

  it('does not overwrite a passkey already attached to the entry', () => {
    const entry = createEntry();
    addPasskeyToEntry(entry, createCredential(), '');

    expect(() => addPasskeyToEntry(entry, createCredential(), '')).toThrow(
      'Entry already contains a passkey',
    );
  });

  it('uses the login username when the credential username is missing', () => {
    const entry = createEntry();
    addPasskeyToEntry(entry, createCredential({ userName: null }), 'login-user');
    expect(entry.fields.get('KPEX_PASSKEY_USERNAME')).toBe('login-user');
  });

  it('rejects unsupported algorithms and curves', () => {
    expect(() =>
      addPasskeyToEntry(createEntry(), createCredential({ keyCurve: 'P-384' }), ''),
    ).toThrow('Unsupported passkey algorithm or curve');
  });

  it('rejects malformed and non-P-256 private keys without exposing key data', () => {
    const malformedKey = 'not-a-private-key';
    expect(() =>
      addPasskeyToEntry(
        createEntry(),
        createCredential({ keyValue: Buffer.from(malformedKey).toString('base64url') }),
        '',
      ),
    ).toThrow('Invalid passkey private key');

    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'secp384r1' });
    expect(() =>
      addPasskeyToEntry(
        createEntry(),
        createCredential({
          keyValue: privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64url'),
        }),
        '',
      ),
    ).toThrow('Invalid passkey private key');
  });

  it('rejects malformed user handles', () => {
    expect(() =>
      addPasskeyToEntry(createEntry(), createCredential({ userHandle: '!' }), ''),
    ).toThrow('Invalid base64url');
  });
});
