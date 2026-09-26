import config from "config";
import {ClientType} from "../db/types.js";

// Env-var overrides arrive as strings (e.g. "true", "false", "1"), but config.get<boolean>
// returns the raw value. JS truthiness considers "false" truthy, which silently breaks
// every boolean toggle when sourced from an env var. Coerce here.
export function getBool(key: string): boolean {
  const value = config.get<unknown>(key);
  if (typeof value === "boolean") return value;
  if (typeof value === "string") return value.toLowerCase() === "true";
  if (typeof value === "number") return value !== 0;
  return false;
}

export interface ClientConfig {
  _id: string;
  redirectUris: string[];
  type: ClientType;
  clientSecret: string | null;
  allowedTokenGrant: boolean;
  expiry: number;
  disabled: string | null;
}

let cachedClient: ClientConfig | null = null;

export function getClient(clientId: string): ClientConfig | null {
  if (!config.has("client.clientId")) return null;

  const configClientId = config.get<string>("client.clientId");
  if (clientId !== configClientId) return null;

  if (!cachedClient) {
    const clientSecret = config.has("client.clientSecret")
      ? config.get<string>("client.clientSecret")
      : null;

    cachedClient = {
      _id: configClientId,
      redirectUris: config.get<string[]>("client.redirectUris"),
      type: clientSecret ? ClientType.Confidential : ClientType.Public,
      clientSecret,
      allowedTokenGrant: config.has("client.allowedTokenGrant")
        ? getBool("client.allowedTokenGrant")
        : false,
      expiry: config.has("client.expiry")
        ? config.get<number>("client.expiry")
        : 10080,
      disabled: null,
    };
  }

  return cachedClient;
}
