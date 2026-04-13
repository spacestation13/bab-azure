import config from "config";

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
