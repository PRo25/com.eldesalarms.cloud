const API_URL = 'https://cloud.eldesalarms.com:8083/api';
const REQUEST_TIMEOUT = 10_000;

type JsonRecord = Record<string, unknown>;
type ApiLogger = (message: string) => void;

const SENSITIVE_KEY = /password|pin(?:code)?|passphrase|token|authorization|cookie|secret|credential/i;
const MAX_LOG_BODY_LENGTH = 32_000;

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function collectSensitiveValues(value: unknown, values: string[] = []): string[] {
  if (Array.isArray(value)) {
    value.forEach((item) => collectSensitiveValues(item, values));
  } else if (isRecord(value)) {
    Object.entries(value).forEach(([key, item]) => {
      if (SENSITIVE_KEY.test(key) && typeof item === 'string' && item.length > 0) {
        values.push(item);
      } else {
        collectSensitiveValues(item, values);
      }
    });
  }

  return values;
}

function redactString(value: string, knownSecrets: string[]): string {
  let redacted = value.replace(/Bearer\s+\S+/gi, 'Bearer [REDACTED]');
  for (const secret of knownSecrets) {
    redacted = redacted.split(secret).join('[REDACTED]');
  }
  redacted = redacted.replace(
    /(["']?)(password|pinCode|pin|passphrase|access[_-]?token|refresh[_-]?token|authorization|secret|credential)\1\s*[:=]\s*["']?[^"',\s}&]+/gi,
    '$2=[REDACTED]',
  );
  return redacted.replace(
    /(<\s*)(password|pinCode|pin|passphrase|access[_-]?token|refresh[_-]?token|authorization|secret|credential)(\s*>)[\s\S]*?(<\/\s*\2\s*>)/gi,
    '$1$2$3[REDACTED]$4',
  );
}

function redactForLog(value: unknown, knownSecrets: string[] = []): unknown {
  if (typeof value === 'string') {
    return redactString(value, knownSecrets);
  }
  if (Array.isArray(value)) {
    return value.map((item) => redactForLog(item, knownSecrets));
  }
  if (isRecord(value)) {
    const result: JsonRecord = {};
    Object.entries(value).forEach(([key, item]) => {
      result[key] = SENSITIVE_KEY.test(key) ? '[REDACTED]' : redactForLog(item, knownSecrets);
    });
    return result;
  }
  return value;
}

function formatForLog(value: unknown): string {
  let output: string;
  try {
    const serialized = typeof value === 'string' ? value : JSON.stringify(value);
    output = typeof serialized === 'string' ? serialized : String(serialized);
  } catch (error) {
    output = error instanceof Error ? `Unserializable value (${error.name})` : 'Unserializable value';
  }
  return output.length > MAX_LOG_BODY_LENGTH
    ? `${output.slice(0, MAX_LOG_BODY_LENGTH)}...[truncated]`
    : output;
}

function redactUrl(url: string): string {
  return url.replace(
    /([?&])([^=&#]+)=([^&#]*)/g,
    (match, separator: string, key: string) => (
      SENSITIVE_KEY.test(key) ? `${separator}${key}=[REDACTED]` : match
    ),
  );
}

function redactHeaders(headers: Record<string, string>): Record<string, string> {
  const result: Record<string, string> = {};
  Object.entries(headers).forEach(([key, value]) => {
    if (!SENSITIVE_KEY.test(key)) {
      result[key] = value;
    }
  });
  return result;
}

function getRedactedResponseHeaders(response: Response): Record<string, string> {
  const result: Record<string, string> = {};
  response.headers.forEach((value, key) => {
    if (!SENSITIVE_KEY.test(key)) {
      result[key] = value;
    }
  });
  return result;
}

async function logResponse(
  logger: ApiLogger | undefined,
  method: string,
  url: string,
  response: Response,
  knownSecrets: string[],
  startedAt: number,
): Promise<string> {
  let body = '';
  try {
    body = await response.clone().text();
  } catch (error) {
    body = `Could not read response body: ${error instanceof Error ? error.message : String(error)}`;
  }

  let safeBody: unknown = '';
  if (body.trim().length > 0) {
    try {
      safeBody = redactForLog(JSON.parse(body) as unknown, knownSecrets);
    } catch (error) {
      safeBody = {
        raw: redactString(body, knownSecrets),
        parseError: error instanceof Error ? error.name : 'Unknown parse error',
      };
    }
  }

  logger?.(
    `\n[ELDES API DEBUG] \nResponse status=${response.status} ${method} ${redactUrl(url)} `
    + `\ndurationMs=${Date.now() - startedAt} headers=${formatForLog(getRedactedResponseHeaders(response))} `
    + `\nbody=${formatForLog(safeBody)}`,
  );

  return formatForLog(safeBody);
}

async function sendRequest(
  url: string,
  options: RequestInit,
  headers: Record<string, string>,
  logger?: ApiLogger,
  additionalSecrets: string[] = [],
): Promise<Response> {
  const method = options.method ?? 'GET';
  const requestBody = typeof options.body === 'string' ? options.body : undefined;
  let parsedBody: unknown = requestBody;
  if (requestBody) {
    try {
      parsedBody = JSON.parse(requestBody) as unknown;
    } catch (error) {
      parsedBody = {
        raw: requestBody,
        parseError: error instanceof Error ? error.name : 'Unknown parse error',
      };
    }
  }
  const knownSecrets = collectSensitiveValues(parsedBody);
  knownSecrets.push(...additionalSecrets.filter((secret) => secret.length > 0));
  const safeUrl = redactUrl(url);
  const startedAt = Date.now();
  logger?.(
    `\n[ELDES API DEBUG] \nRequest ${method} ${safeUrl} `
    + `\nheaders=${formatForLog(redactHeaders(headers))} `
    + `\nbody=${formatForLog(redactForLog(parsedBody, knownSecrets))}`,
  );

  try {
    const response = await fetch(url, options);
    await logResponse(logger, method, url, response, knownSecrets, startedAt);
    return response;
  } catch (error) {
    logger?.(
      `\n[ELDES API DEBUG] \nRequest failed ${method} ${safeUrl} `
      + `\ndurationMs=${Date.now() - startedAt} \nerror=${redactString(
        error instanceof Error ? `${error.name}: ${error.message}` : String(error),
        knownSecrets,
      )}`,
    );
    throw error;
  }
}

export type EldesPartition = {
  internalId?: string | number;
  name?: string;
  armed?: boolean;
  armStay?: boolean;
  state?: string;
  hasUnacceptedPartitionAlarms?: boolean;
};

export type EldesPartitionStatus = {
  hasActiveFaults?: boolean;
  partitions: EldesPartition[];
};

export type EldesAlarmStatus = 'armed' | 'stay_armed' | 'disarmed';

export type EldesAlarmMode = 'arm' | 'armstay' | 'disarm';

export type EldesInstallation = {
  imei: string;
  name: string;
  partitions: EldesPartition[];
};

function getToken(value: unknown, key: string): string | undefined {
  if (!isRecord(value) || typeof value[key] !== 'string' || value[key].length === 0) {
    return undefined;
  }

  return value[key];
}

function parsePartition(value: unknown): EldesPartition {
  if (!isRecord(value)) {
    throw new Error('ELDES returned an invalid partition.');
  }

  return {
    internalId: typeof value.internalId === 'string' || typeof value.internalId === 'number'
      ? value.internalId
      : undefined,
    name: typeof value.name === 'string' ? value.name : undefined,
    armed: typeof value.armed === 'boolean' ? value.armed : undefined,
    armStay: typeof value.armStay === 'boolean' ? value.armStay : undefined,
    state: typeof value.state === 'string' ? value.state : undefined,
    hasUnacceptedPartitionAlarms: typeof value.hasUnacceptedPartitionAlarms === 'boolean'
      ? value.hasUnacceptedPartitionAlarms
      : undefined,
  };
}

export function mapEldesAlarmState(state: string | undefined): EldesAlarmStatus | undefined {
  switch (state?.trim().toUpperCase()) {
    case 'DISARMED':
      return 'disarmed';
    case 'ARMED':
      return 'armed';
    case 'ARMSTAY':
      return 'stay_armed';
    default:
      return undefined;
  }
}

export default class EldesCloudApi {

  private accessToken: string | undefined;

  private refreshToken: string;

  constructor(
    refreshToken: string,
    private readonly hostDeviceId: string,
    private readonly onRefreshToken?: (token: string) => Promise<void>,
    private readonly logger?: ApiLogger,
  ) {
    this.refreshToken = refreshToken;
  }

  static async login(
    email: string,
    password: string,
    hostDeviceId: string,
    logger?: ApiLogger,
  ): Promise<EldesCloudApi> {
    const headers = {
      'X-Requested-With': 'XMLHttpRequest',
      'User-Agent': 'okhttp/3.11.0',
      'x-whitelable': 'eldes',
      'Content-Type': 'application/json; charset=UTF-8',
    };
    const response = await sendRequest(`${API_URL}/auth/login`, {
      method: 'POST',
      headers,
      signal: AbortSignal.timeout(REQUEST_TIMEOUT),
      body: JSON.stringify({
        email,
        password,
        hostDeviceId,
      }),
    }, headers, logger);

    if (!response.ok) {
      throw new Error(`ELDES login failed (HTTP ${response.status}). Check the email and password and try again.`);
    }

    const result: unknown = await response.json();
    const accessToken = getToken(result, 'token');
    const refreshToken = getToken(result, 'refreshToken');
    if (!accessToken || !refreshToken) {
      throw new Error('ELDES login succeeded but did not return the required session tokens.');
    }

    const client = new EldesCloudApi(refreshToken, hostDeviceId, undefined, logger);
    client.accessToken = accessToken;
    return client;
  }

  getRefreshToken(): string {
    return this.refreshToken;
  }

  async getInstallations(): Promise<EldesInstallation[]> {
    const response = await this.request('/device/list?showSupportMessages=true');
    const result: unknown = await response.json();
    if (!isRecord(result) || !Array.isArray(result.deviceListEntries)) {
      throw new Error('ELDES returned an invalid device list.');
    }

    return result.deviceListEntries.map((entry: unknown): EldesInstallation => {
      if (!isRecord(entry) || typeof entry.imei !== 'string' || entry.imei.length === 0) {
        throw new Error('ELDES returned a device without a valid identifier.');
      }

      const partitions = Array.isArray(entry.partitions)
        ? entry.partitions.map(parsePartition)
        : [];

      return {
        imei: entry.imei,
        name: typeof entry.name === 'string' && entry.name.length > 0 ? entry.name : entry.imei,
        partitions,
      };
    });
  }

  async getPartitionStatuses(imei: string, pinCode: string): Promise<EldesPartitionStatus> {
    const response = await this.request(
      `/device/partition/list?imei=${encodeURIComponent(imei)}`,
      'POST',
      { pinCode },
    );
    const result: unknown = await response.json();
    if (!isRecord(result) || !Array.isArray(result.partitions)) {
      throw new Error('ELDES returned an invalid partition status list.');
    }

    return {
      hasActiveFaults: typeof result.hasActiveFaults === 'boolean' ? result.hasActiveFaults : undefined,
      partitions: result.partitions.map(parsePartition),
    };
  }

  async setAlarm(
    mode: EldesAlarmMode,
    imei: string,
    partitionIndex: string | number,
    pinCode: string,
  ): Promise<void> {
    await this.request(`/device/action/${mode}`, 'POST', {
      imei,
      partitionIndex,
      pinCode,
    });
  }

  private async refreshAccessToken(): Promise<void> {
    const headers = Object.assign(this.getHeaders(), {
      Authorization: `Bearer ${this.refreshToken}`,
    });
    const response = await sendRequest(`${API_URL}/auth/token`, {
      method: 'GET',
      headers,
      signal: AbortSignal.timeout(REQUEST_TIMEOUT),
    }, headers, this.logger, [this.refreshToken, this.accessToken ?? '']);

    if (response.status === 401) {
      throw new Error('The ELDES session expired. Repair the device and log in again.');
    }
    if (!response.ok) {
      throw new Error(`ELDES session refresh failed (HTTP ${response.status}).`);
    }

    const result: unknown = await response.json();
    const accessToken = getToken(result, 'token');
    if (!accessToken) {
      throw new Error('ELDES session refresh did not return an access token.');
    }

    this.accessToken = accessToken;
    const refreshToken = getToken(result, 'refreshToken');
    if (refreshToken && refreshToken !== this.refreshToken) {
      this.refreshToken = refreshToken;
      await this.onRefreshToken?.(refreshToken);
    }
  }

  private async request(
    path: string,
    method: 'GET' | 'POST' = 'GET',
    body?: unknown,
  ): Promise<Response> {
    if (!this.accessToken) {
      await this.refreshAccessToken();
    }

    let response = await this.requestWithAccessToken(path, method, body);
    if (response.status === 401) {
      await this.refreshAccessToken();
      response = await this.requestWithAccessToken(path, method, body);
    }

    if (!response.ok) {
      throw new Error(
        `ELDES API request failed (HTTP ${response.status}); see the sanitized ELDES API response log for details.`,
      );
    }

    return response;
  }

  private async requestWithAccessToken(
    path: string,
    method: 'GET' | 'POST',
    body?: unknown,
  ): Promise<Response> {
    const headers = Object.assign(this.getHeaders(), {
      Authorization: `Bearer ${this.accessToken}`,
    });
    const requestOptions: RequestInit = {
      method,
      headers,
      signal: AbortSignal.timeout(REQUEST_TIMEOUT),
    };
    if (body !== undefined) {
      requestOptions.body = JSON.stringify(body);
    }

    return sendRequest(
      `${API_URL}${path}`,
      requestOptions,
      headers,
      this.logger,
      [this.refreshToken, this.accessToken ?? ''],
    );
  }

  private getHeaders(): Record<string, string> {
    return {
      'X-Requested-With': 'XMLHttpRequest',
      'User-Agent': 'okhttp/3.11.0',
      'x-whitelable': 'eldes',
      'Content-Type': 'application/json; charset=UTF-8',
    };
  }

}
