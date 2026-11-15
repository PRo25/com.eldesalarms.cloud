import Homey from 'homey';
// ESLint's Node resolver does not map Node.js .js specifiers to TypeScript source files.
// eslint-disable-next-line import/no-unresolved, import/extensions, node/no-missing-import
import EldesCloudApi from '../../lib/eldes-cloud-api.js';
// eslint-disable-next-line import/no-unresolved, import/extensions, node/no-missing-import
import { mapEldesAlarmState, type EldesAlarmMode, type EldesAlarmStatus } from '../../lib/eldes-cloud-api.js';
// ESLint's Node resolver does not map Node.js .js specifiers to TypeScript source files.
// eslint-disable-next-line import/no-unresolved, import/extensions, node/no-missing-import
import { decryptSecret, encryptSecret, type EncryptedSecret } from '../../lib/encrypted-secret.js';
// ESLint's Node resolver does not map Node.js .js specifiers to TypeScript source files.
// eslint-disable-next-line import/no-unresolved, import/extensions, node/no-missing-import
import type AlarmSystemDriver from './driver.js';

const LEGACY_REFRESH_TOKEN_KEY = 'eldesRefreshToken';
const ENCRYPTED_REFRESH_TOKEN_KEY = 'eldesEncryptedRefreshToken';
const TOKEN_SALT_KEY = 'eldesTokenSalt';
const TOKEN_IV_KEY = 'eldesTokenIv';
const TOKEN_AUTH_TAG_KEY = 'eldesTokenAuthTag';
const HOST_DEVICE_ID_KEY = 'eldesHostDeviceId';
const ENCRYPTED_PIN_KEY = 'eldesEncryptedPin';
const PIN_SALT_KEY = 'eldesPinSalt';
const PIN_IV_KEY = 'eldesPinIv';
const PIN_AUTH_TAG_KEY = 'eldesPinAuthTag';
const STATUS_CAPABILITY = 'eldes_alarm_status';
const ACTIVE_FAULTS_CAPABILITY = 'eldes_active_faults';
const UNACCEPTED_PARTITION_ALARMS_CAPABILITY = 'eldes_unaccepted_partition_alarms';
const COMMAND_CAPABILITIES: Record<EldesAlarmMode, string> = {
  arm: 'eldes_alarm_arm',
  armstay: 'eldes_alarm_stay_arm',
  disarm: 'eldes_alarm_disarm',
};
const REPORTED_STATUS_CAPABILITIES = {
  armed_disarmed: 'eldes_reported_armed_disarmed',
  stay_armed_disarmed: 'eldes_reported_stay_armed_disarmed',
};
const LEGACY_REPORTED_STATUS_CAPABILITIES = [
  'eldes_reported_armed',
  'eldes_reported_home_armed',
  'eldes_reported_disarmed',
];
const LEGACY_ALARM_CAPABILITIES = ['alarm_arm_state', 'homealarm_state'];
const COMMAND_AUDIT_CAPABILITIES: Record<EldesAlarmMode, string> = {
  arm: 'eldes_homey_arm_request',
  armstay: 'eldes_homey_stay_arm_request',
  disarm: 'eldes_homey_disarm_request',
};
const POLL_INTERVAL_SETTING = 'poll_interval_seconds';
const DEFAULT_POLL_INTERVAL_SECONDS = 30;
const MIN_POLL_INTERVAL_SECONDS = 5;
const MAX_POLL_INTERVAL_SECONDS = 300;

type AlarmDeviceData = {
  id: string;
  imei: string;
  partitionIndex: string | number;
};

function parseAlarmDeviceData(value: unknown): AlarmDeviceData {
  if (typeof value !== 'object' || value === null) {
    throw new Error('The saved ELDES device information is incomplete.');
  }

  const data = value as Record<string, unknown>;
  if (
    typeof data.id !== 'string'
    || typeof data.imei !== 'string'
    || (typeof data.partitionIndex !== 'string' && typeof data.partitionIndex !== 'number')
  ) {
    throw new Error('The saved ELDES device information is incomplete.');
  }

  return {
    id: data.id,
    imei: data.imei,
    partitionIndex: data.partitionIndex,
  };
}

function readEncryptedToken(store: Record<string, unknown>): EncryptedSecret {
  const ciphertext = store[ENCRYPTED_REFRESH_TOKEN_KEY];
  const salt = store[TOKEN_SALT_KEY];
  const iv = store[TOKEN_IV_KEY];
  const authTag = store[TOKEN_AUTH_TAG_KEY];
  if (
    typeof ciphertext !== 'string'
    || typeof salt !== 'string'
    || typeof iv !== 'string'
    || typeof authTag !== 'string'
  ) {
    throw new Error('The encrypted ELDES token is missing. Repair the device to sign in again.');
  }

  return {
    ciphertext,
    salt,
    iv,
    authTag,
  };
}

function readEncryptedPin(store: Record<string, unknown>): EncryptedSecret {
  const ciphertext = store[ENCRYPTED_PIN_KEY];
  const salt = store[PIN_SALT_KEY];
  const iv = store[PIN_IV_KEY];
  const authTag = store[PIN_AUTH_TAG_KEY];
  if (
    typeof ciphertext !== 'string'
    || typeof salt !== 'string'
    || typeof iv !== 'string'
    || typeof authTag !== 'string'
  ) {
    throw new Error('The encrypted ELDES alarm PIN is missing. Repair the device to sign in again.');
  }

  return {
    ciphertext,
    salt,
    iv,
    authTag,
  };
}

export default class AlarmSystemDevice extends Homey.Device {

  private pollTimer: ReturnType<typeof setInterval> | undefined;

  private encryptionPassphrase: string | undefined;

  private pinCode: string | undefined;

  private apiClient: EldesCloudApi | undefined;

  private isPolling = false;

  private commandAuditQueue: Promise<void> = Promise.resolve();

  async onInit(): Promise<void> {
    if (this.getClass() !== 'other') {
      await this.setClass('other');
    }

    for (const capability of [
      ...LEGACY_ALARM_CAPABILITIES,
      ...LEGACY_REPORTED_STATUS_CAPABILITIES,
    ]) {
      if (this.hasCapability(capability)) {
        await this.removeCapability(capability);
      }
    }

    for (const capability of [
      ...Object.values(COMMAND_AUDIT_CAPABILITIES),
      ...Object.values(REPORTED_STATUS_CAPABILITIES),
      ACTIVE_FAULTS_CAPABILITY,
      UNACCEPTED_PARTITION_ALARMS_CAPABILITY,
    ]) {
      if (!this.hasCapability(capability)) {
        await this.addCapability(capability);
      }
    }

    this.registerCapabilityListener(COMMAND_CAPABILITIES.arm, (value: boolean) => (
      this.handleAlarmCommand('arm', value)
    ));
    this.registerCapabilityListener(COMMAND_CAPABILITIES.armstay, (value: boolean) => (
      this.handleAlarmCommand('armstay', value)
    ));
    this.registerCapabilityListener(COMMAND_CAPABILITIES.disarm, (value: boolean) => (
      this.handleAlarmCommand('disarm', value)
    ));

    if (typeof this.getStoreValue(LEGACY_REFRESH_TOKEN_KEY) === 'string') {
      await this.unsetStoreValue(LEGACY_REFRESH_TOKEN_KEY);
      await this.setUnavailable('The ELDES token needs to be re-encrypted. Repair this device to sign in again.');
      return;
    }

    const deviceData = parseAlarmDeviceData(this.getData());
    this.encryptionPassphrase = (this.driver as AlarmSystemDriver)
      .getEncryptionPassphrase(deviceData.id);

    if (!this.encryptionPassphrase) {
      await this.setUnavailable('Enter your encryption passphrase by repairing this device.');
      return;
    }

    this.apiClient = this.createApiClient(this.encryptionPassphrase);
    await this.startPolling();
  }

  async onUninit(): Promise<void> {
    if (this.pollTimer) {
      this.homey.clearInterval(this.pollTimer);
      this.pollTimer = undefined;
    }
    this.encryptionPassphrase = undefined;
    this.pinCode = undefined;
    this.apiClient = undefined;
  }

  async setEncryptionPassphrase(passphrase: string): Promise<void> {
    const apiClient = this.createApiClient(passphrase);
    this.encryptionPassphrase = passphrase;
    this.apiClient = apiClient;
    await this.startPolling();
  }

  async onSettings({
    newSettings,
    changedKeys,
  }: {
    newSettings: Record<string, unknown>;
    changedKeys: string[];
  }): Promise<void> {
    if (!changedKeys.includes(POLL_INTERVAL_SETTING)) {
      return;
    }

    const intervalSeconds = newSettings[POLL_INTERVAL_SETTING];
    if (
      typeof intervalSeconds !== 'number'
      || !Number.isInteger(intervalSeconds)
      || intervalSeconds < MIN_POLL_INTERVAL_SECONDS
      || intervalSeconds > MAX_POLL_INTERVAL_SECONDS
    ) {
      throw new Error(
        `Choose a polling interval from ${MIN_POLL_INTERVAL_SECONDS} to ${MAX_POLL_INTERVAL_SECONDS} seconds.`,
      );
    }

    await this.startPolling(intervalSeconds);
  }

  private getPollingIntervalSeconds(): number {
    const intervalSeconds = this.getSetting(POLL_INTERVAL_SETTING);
    if (intervalSeconds === undefined || intervalSeconds === null) {
      return DEFAULT_POLL_INTERVAL_SECONDS;
    }
    if (
      typeof intervalSeconds !== 'number'
      || !Number.isInteger(intervalSeconds)
      || intervalSeconds < MIN_POLL_INTERVAL_SECONDS
      || intervalSeconds > MAX_POLL_INTERVAL_SECONDS
    ) {
      throw new Error(
        `The polling interval must be from ${MIN_POLL_INTERVAL_SECONDS} to ${MAX_POLL_INTERVAL_SECONDS} seconds.`,
      );
    }

    return intervalSeconds;
  }

  private async startPolling(
    intervalSeconds = this.getPollingIntervalSeconds(),
  ): Promise<void> {
    if (this.pollTimer) {
      this.homey.clearInterval(this.pollTimer);
      this.pollTimer = undefined;
    }

    await this.refreshStatus();
    this.pollTimer = this.homey.setInterval(() => {
      this.refreshStatus().catch((error: unknown) => this.error(error));
    }, intervalSeconds * 1000);
  }

  private async refreshStatus(): Promise<void> {
    if (this.isPolling) {
      return;
    }

    this.isPolling = true;
    try {
      if (!this.encryptionPassphrase || !this.pinCode || !this.apiClient) {
        await this.setUnavailable('Enter your encryption passphrase by repairing this device.');
        return;
      }

      const deviceData = parseAlarmDeviceData(this.getData());
      const partitionStatus = await this.apiClient.getPartitionStatuses(deviceData.imei, this.pinCode);
      const { partitions } = partitionStatus;
      const partition = partitions.find(
        (item) => item.internalId === deviceData.partitionIndex,
      );
      if (!partition) {
        throw new Error('The paired ELDES alarm partition was not found.');
      }
      const status = mapEldesAlarmState(partition.state);
      if (!status) {
        const apiState = partition.state ? ` (${partition.state})` : '';
        throw new Error(`ELDES did not provide a supported arming status for this partition${apiState}.`);
      }

      await this.setCapabilityValue(STATUS_CAPABILITY, status);
      await this.updateReportedStatusCapabilities(status);
      if (typeof partitionStatus.hasActiveFaults === 'boolean') {
        await this.setCapabilityValue(ACTIVE_FAULTS_CAPABILITY, partitionStatus.hasActiveFaults);
      }
      if (typeof partition.hasUnacceptedPartitionAlarms === 'boolean') {
        await this.setCapabilityValue(
          UNACCEPTED_PARTITION_ALARMS_CAPABILITY,
          partition.hasUnacceptedPartitionAlarms,
        );
      }
      await this.setAvailable();
    } catch (error) {
      const message = error instanceof Error ? error.message : 'An unexpected ELDES API error occurred.';
      this.error(message);
      await this.setUnavailable(message);
    } finally {
      this.isPolling = false;
    }
  }

  private async updateReportedStatusCapabilities(status: EldesAlarmStatus): Promise<void> {
    if (status === 'armed') {
      await this.setCapabilityValue(REPORTED_STATUS_CAPABILITIES.armed_disarmed, true);
    } else if (status === 'home_armed') {
      await this.setCapabilityValue(REPORTED_STATUS_CAPABILITIES.stay_armed_disarmed, true);
    } else {
      await Promise.all([
        this.setCapabilityValue(REPORTED_STATUS_CAPABILITIES.armed_disarmed, false),
        this.setCapabilityValue(REPORTED_STATUS_CAPABILITIES.stay_armed_disarmed, false),
      ]);
    }
  }

  private async handleAlarmCommand(mode: EldesAlarmMode, value: boolean): Promise<void> {
    if (!value) {
      await this.refreshStatus();
      return;
    }

    if (!this.apiClient || !this.pinCode) {
      throw new Error('Repair this device and sign in to ELDES before controlling the alarm.');
    }

    const deviceData = parseAlarmDeviceData(this.getData());
    try {
      await this.apiClient.setAlarm(
        mode,
        deviceData.imei,
        deviceData.partitionIndex,
        this.pinCode,
      );
      await this.recordHomeyCommand(mode);
      await this.refreshStatus();
    } catch (error) {
      await this.refreshStatus();
      throw error;
    }
  }

  private async recordHomeyCommand(mode: EldesAlarmMode): Promise<void> {
    const capability = COMMAND_AUDIT_CAPABILITIES[mode];
    const update = this.commandAuditQueue.then(async () => {
      const currentValue = this.getCapabilityValue(capability);
      await this.setCapabilityValue(capability, currentValue !== true);
    });

    this.commandAuditQueue = update.catch((error: unknown) => {
      this.error(`Could not record the Homey ${mode} command in the device Timeline.`, error);
    });
    await this.commandAuditQueue;
  }

  private async persistEncryptedToken(token: string, passphrase: string): Promise<void> {
    const encryptedToken = encryptSecret(token, passphrase);
    await this.setStoreValue(ENCRYPTED_REFRESH_TOKEN_KEY, encryptedToken.ciphertext);
    await this.setStoreValue(TOKEN_SALT_KEY, encryptedToken.salt);
    await this.setStoreValue(TOKEN_IV_KEY, encryptedToken.iv);
    await this.setStoreValue(TOKEN_AUTH_TAG_KEY, encryptedToken.authTag);
  }

  private createApiClient(passphrase: string): EldesCloudApi {
    const store = this.getStore();
    const encryptedToken = readEncryptedToken(store);
    const refreshToken = decryptSecret(encryptedToken, passphrase);
    this.pinCode = decryptSecret(readEncryptedPin(store), passphrase);
    const hostDeviceId = store[HOST_DEVICE_ID_KEY];
    if (typeof hostDeviceId !== 'string') {
      throw new Error('The saved ELDES device information is incomplete. Repair this device to sign in again.');
    }

    return new EldesCloudApi(
      refreshToken,
      hostDeviceId,
      async (token) => this.persistEncryptedToken(token, passphrase),
      (message) => {
        if (this.getSetting('api_debug_logging') !== false) {
          this.log(message);
        }
      },
    );
  }

}
