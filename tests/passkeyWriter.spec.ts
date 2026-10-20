import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import type { Fido2Credential, Item, Organization } from '../src/bitwardenCliTypes';
import type { BitwardenData } from '../src/bitwardenExtractor';
import { KeePassWriter } from '../src/keepassWriter';
import { ProtectedValue, type Kdbx } from '../src/kdbxweb';

function createCredential(): Fido2Credential {
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return {
    credentialId: '010203',
    keyAlgorithm: 'ECDSA',
    keyCurve: 'P-256',
    keyValue: privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64url'),
    rpId: 'example.com',
    userHandle: 'AQID',
    userName: 'alice',
  };
}

function createItem(fido2Credentials: Fido2Credential[] = []): Item {
  return {
    id: 'item-id',
    name: 'Example account',
    type: 1,
    reprompt: 0,
    revisionDate: '2026-01-01T00:00:00.000Z',
    creationDate: '2026-01-01T00:00:00.000Z',
    favorite: false,
    collectionIds: ['collection-a', 'collection-b'],
    organizationId: 'organization-id',
    login: {
      fido2Credentials,
      uris: [],
      username: 'alice',
    },
  };
}

function createData(item: Item): BitwardenData {
  const organization: Organization = {
    object: 'organization',
    id: 'organization-id',
    name: 'Example organization',
    status: 0,
    type: 0,
    enabled: true,
  };
  return {
    organizations: [organization],
    collections: [
      {
        object: 'collection',
        id: 'collection-a',
        name: 'Collection A',
        organizationId: organization.id,
      },
      {
        object: 'collection',
        id: 'collection-b',
        name: 'Collection B',
        organizationId: organization.id,
      },
    ],
    folders: [{ object: 'folder', name: 'No Folder' }],
    items: [item],
    attachments: {},
  };
}

function createWriter(organizationMode: 'flat' | 'nested') {
  return new KeePassWriter({
    name: 'Test database',
    password: 'test-password',
    organizationMode,
    organizationFolderNames: {
      organizations: 'Organizations',
      folders: 'Folders',
      collections: 'Collections',
    },
  });
}

function getEntries(writer: KeePassWriter) {
  const db = (writer as unknown as { db: Kdbx }).db;
  return [...db.getDefaultGroup().allEntries()];
}

describe('KeePassWriter passkey export', () => {
  it('writes the passkey to each organization/collection entry copy', async () => {
    const writer = createWriter('nested');
    await writer.fillDatabaseWithBitwardenData(createData(createItem([createCredential()])));

    const entries = getEntries(writer);
    expect(entries).toHaveLength(3);
    for (const entry of entries) {
      expect(entry.tags).toContain('Passkey');
      expect(entry.fields.get('KPEX_PASSKEY_CREDENTIAL_ID')).toBeInstanceOf(ProtectedValue);
      expect(
        (
          entry.fields.get('KPEX_PASSKEY_CREDENTIAL_ID') as InstanceType<typeof ProtectedValue>
        ).getText(),
      ).toBe('AQID');
    }
  });

  it('rejects multiple passkeys instead of overwriting one', async () => {
    const writer = createWriter('flat');
    await expect(
      writer.fillDatabaseWithBitwardenData(
        createData(createItem([createCredential(), createCredential()])),
      ),
    ).rejects.toThrow('contains multiple passkeys');
  });

  it('preserves login entries without passkeys', async () => {
    const writer = createWriter('flat');
    await writer.fillDatabaseWithBitwardenData(createData(createItem()));

    const [entry] = getEntries(writer);
    expect(entry.tags).toContain('Login');
    expect(entry.tags).not.toContain('Passkey');
    expect(entry.fields.has('KPEX_PASSKEY_CREDENTIAL_ID')).toBe(false);
  });
});
