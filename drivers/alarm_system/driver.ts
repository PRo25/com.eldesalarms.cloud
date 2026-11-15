import { randomUUID } from 'node:crypto';
import Homey from 'homey';
// ESLint's Node resolver does not map Node.js .js specifiers to TypeScript source files.
// eslint-disable-next-line import/no-unresolved, import/extensions, node/no-missing-import
import EldesCloudApi, { type EldesInstallation } from '../../lib/eldes-cloud-api.js';
// eslint-disable-next-line import/no-unresolved, import/extensions, node/no-missing-import
import type AlarmSystemDevice from './device.js';
// eslint-disable-next-line import/no-unresolved, import/extensions, node/no-missing-import
import { encryptSecret } from '../../lib/encrypted-secret.js';

const ENCRYPTED_REFRESH_TOKEN_KEY = 'eldesEncryptedRefreshToken';
const TOKEN_SALT_KEY = 'eldesTokenSalt';
const TOKEN_IV_KEY = 'eldesTokenIv';
const TOKEN_AUTH_TAG_KEY = 'eldesTokenAuthTag';
const HOST_DEVICE_ID_KEY = 'eldesHostDeviceId';
const ENCRYPTED_PIN_KEY = 'eldesEncryptedPin';
const PIN_SALT_KEY = 'eldesPinSalt';
const PIN_IV_KEY = 'eldesPinIv';
const PIN_AUTH_TAG_KEY = 'eldesPinAuthTag';

type LoginData = {
  username: string;
  password: string;
  pinCode: string;
  encryptionPassphrase: string;
};

type AlarmDeviceData = {
  id: string;
  imei: string;
  partitionIndex: string | number;
};

type CachedPassphrase = {
  value: string;
  timeout: ReturnType<typeof setTimeout>;
};

function parseLoginData(value: unknown): LoginData {
  if (typeof value !== 'object' || value === null) {
    throw new Error('Enter your ELDES account email and password.');
  }

  const credentials = value as Record<string, unknown>;
  if (
    typeof credentials.username !== 'string'
    || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(credentials.username)
    || typeof credentials.password !== 'string'
    || credentials.password.length === 0
    || typeof credentials.pinCode !== 'string'
    || credentials.pinCode.length === 0
    || typeof credentials.encryptionPassphrase !== 'string'
    || credentials.encryptionPassphrase.length < 12
  ) {
    throw new Error('Enter your ELDES email, password, alarm PIN, and an encryption passphrase of at least 12 characters.');
  }

  return {
    username: credentials.username.trim(),
    password: credentials.password,
    pinCode: credentials.pinCode,
    encryptionPassphrase: credentials.encryptionPassphrase,
  };
}

function parseAlarmDeviceData(device: Homey.Device): AlarmDeviceData {
  const value = device.getData();
  if (
    typeof value.id !== 'string'
    || typeof value.imei !== 'string'
    || (typeof value.partitionIndex !== 'string' && typeof value.partitionIndex !== 'number')
  ) {
    throw new Error('The saved ELDES device information is incomplete.');
  }

  return {
    id: value.id,
    imei: value.imei,
    partitionIndex: value.partitionIndex,
  };
}

function toPairingDevices(
  installations: EldesInstallation[],
  refreshToken: string,
  pinCode: string,
  hostDeviceId: string,
  encryptionPassphrase: string,
  cachePassphrase: (deviceId: string, passphrase: string) => void,
): object[] {
  const devices = installations.flatMap((installation) => installation.partitions.flatMap((partition) => {
    if (partition.internalId === undefined) {
      return [];
    }

    const partitionName = partition.name ?? `Partition ${partition.internalId}`;
    const id = `${installation.imei}:${partition.internalId}`;
    const encryptedToken = encryptSecret(refreshToken, encryptionPassphrase);
    const encryptedPin = encryptSecret(pinCode, encryptionPassphrase);
    cachePassphrase(id, encryptionPassphrase);
    return [{
      name: `${installation.name} - ${partitionName}`,
      data: {
        id,
        imei: installation.imei,
        partitionIndex: partition.internalId,
      },
      store: {
        [ENCRYPTED_REFRESH_TOKEN_KEY]: encryptedToken.ciphertext,
        [TOKEN_SALT_KEY]: encryptedToken.salt,
        [TOKEN_IV_KEY]: encryptedToken.iv,
        [TOKEN_AUTH_TAG_KEY]: encryptedToken.authTag,
        [ENCRYPTED_PIN_KEY]: encryptedPin.ciphertext,
        [PIN_SALT_KEY]: encryptedPin.salt,
        [PIN_IV_KEY]: encryptedPin.iv,
        [PIN_AUTH_TAG_KEY]: encryptedPin.authTag,
        [HOST_DEVICE_ID_KEY]: hostDeviceId,
      },
    }];
  }));

  if (devices.length === 0) {
    throw new Error('No ELDES alarm partitions were found in this account.');
  }

  return devices;
}

export default class AlarmSystemDriver extends Homey.Driver {

  private readonly encryptionPassphrases = new Map<string, CachedPassphrase>();

  private cacheEncryptionPassphrase(deviceId: string, passphrase: string): void {
    const previous = this.encryptionPassphrases.get(deviceId);
    if (previous) {
      this.homey.clearTimeout(previous.timeout);
    }

    const timeout = this.homey.setTimeout(() => {
      this.encryptionPassphrases.delete(deviceId);
    }, 5 * 60_000);
    this.encryptionPassphrases.set(deviceId, { value: passphrase, timeout });
  }

  getEncryptionPassphrase(deviceId: string): string | undefined {
    const cached = this.encryptionPassphrases.get(deviceId);
    if (cached) {
      this.homey.clearTimeout(cached.timeout);
    }
    this.encryptionPassphrases.delete(deviceId);
    return cached?.value;
  }

  async onPair(session: Homey.Driver.PairSession): Promise<void> {
    const hostDeviceId = randomUUID();
    let client: EldesCloudApi | undefined;
    let pinCode: string | undefined;
    let encryptionPassphrase: string | undefined;

    session.setHandler('login', async (data: unknown): Promise<boolean> => {
      const credentials = parseLoginData(data);
      try {
        const candidate = await EldesCloudApi.login(
          credentials.username,
          credentials.password,
          hostDeviceId,
          (message) => this.log(message),
        );
        const installations = await candidate.getInstallations();
        for (const installation of installations) {
          await candidate.getPartitionStatuses(installation.imei, credentials.pinCode);
        }
        client = candidate;
        pinCode = credentials.pinCode;
        encryptionPassphrase = credentials.encryptionPassphrase;
        return true;
      } finally {
        credentials.password = '';
        credentials.pinCode = '';
      }
    });

    session.setHandler('list_devices', async (): Promise<object[]> => {
      if (!client) {
        throw new Error('Log in to your ELDES account before selecting a device.');
      }

      const installations = await client.getInstallations();
      if (!encryptionPassphrase) {
        throw new Error('Enter your encryption passphrase before adding ELDES devices.');
      }
      if (!pinCode) {
        throw new Error('Enter your ELDES alarm PIN before adding devices.');
      }

      return toPairingDevices(
        installations,
        client.getRefreshToken(),
        pinCode,
        hostDeviceId,
        encryptionPassphrase,
        (id, passphrase) => this.cacheEncryptionPassphrase(id, passphrase),
      );
    });
  }

  async onRepair(session: Homey.Driver.PairSession, device?: Homey.Device): Promise<void> {
    if (!device) {
      throw new Error('The ELDES device to repair could not be found.');
    }

    const deviceData = parseAlarmDeviceData(device);

    const savedHostDeviceId = device.getStoreValue(HOST_DEVICE_ID_KEY);
    const hostDeviceId = typeof savedHostDeviceId === 'string' ? savedHostDeviceId : randomUUID();

    session.setHandler('login', async (data: unknown): Promise<boolean> => {
      const credentials: LoginData = parseLoginData(data);

      try {
        const client = await EldesCloudApi.login(
          credentials.username,
          credentials.password,
          hostDeviceId,
          (message) => {
            if (device.getSetting('api_debug_logging') !== false) {
              device.log(message);
            }
          },
        );
        const { partitions } = await client.getPartitionStatuses(deviceData.imei, credentials.pinCode);
        const partitionExists = partitions.some(
          (partition) => partition.internalId === deviceData.partitionIndex,
        );

        if (!partitionExists) {
          throw new Error('This ELDES account does not contain the paired alarm partition.');
        }

        const encryptedToken = encryptSecret(client.getRefreshToken(), credentials.encryptionPassphrase);
        const encryptedPin = encryptSecret(credentials.pinCode, credentials.encryptionPassphrase);
        await device.setStoreValue(ENCRYPTED_REFRESH_TOKEN_KEY, encryptedToken.ciphertext);
        await device.setStoreValue(TOKEN_SALT_KEY, encryptedToken.salt);
        await device.setStoreValue(TOKEN_IV_KEY, encryptedToken.iv);
        await device.setStoreValue(TOKEN_AUTH_TAG_KEY, encryptedToken.authTag);
        await device.setStoreValue(ENCRYPTED_PIN_KEY, encryptedPin.ciphertext);
        await device.setStoreValue(PIN_SALT_KEY, encryptedPin.salt);
        await device.setStoreValue(PIN_IV_KEY, encryptedPin.iv);
        await device.setStoreValue(PIN_AUTH_TAG_KEY, encryptedPin.authTag);
        await device.setStoreValue(HOST_DEVICE_ID_KEY, hostDeviceId);

        const alarmDevice = device as AlarmSystemDevice;
        await alarmDevice.setEncryptionPassphrase(credentials.encryptionPassphrase);
        return true;
      } finally {
        credentials.password = '';
        credentials.pinCode = '';
        credentials.encryptionPassphrase = '';
      }
    });
    await session.showView('credentials');
  }

}
