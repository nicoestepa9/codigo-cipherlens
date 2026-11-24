export interface ParsedTarget {
  host: string;
  port: number;
}

export function parseTarget(input: string): ParsedTarget {
  let target = input.trim();
  if (target.startsWith("https://")) target = target.slice(8);
  else if (target.startsWith("http://")) target = target.slice(7);
  const slash = target.indexOf("/");
  if (slash !== -1) target = target.slice(0, slash);

  const ipv6 = target.match(/^\[([^\]]+)\]:(\d+)$/);
  if (ipv6) return { host: ipv6[1], port: parseInt(ipv6[2], 10) };

  const colonCount = (target.match(/:/g) ?? []).length;
  if (colonCount === 1) {
    const [host, portStr] = target.split(":");
    const port = parseInt(portStr, 10);
    if (!Number.isNaN(port) && port > 0 && port < 65536) {
      return { host, port };
    }
  }

  return { host: target, port: 443 };
}

export function isValidTarget(input: string): boolean {
  const { host } = parseTarget(input);
  return host.length > 0 && host.length <= 253 && !host.includes(" ");
}

function isPrivateIpv4(host: string): boolean {
  const parts = host.split(".").map(Number);
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) {
    return false;
  }
  const [a, b] = parts;
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 100 && b >= 64 && b <= 127)
  );
}

function isPrivateIpv6(host: string): boolean {
  const value = host.toLowerCase();
  return (
    value === "::1" ||
    value === "::" ||
    value.startsWith("fc") ||
    value.startsWith("fd") ||
    value.startsWith("fe80:")
  );
}

export function isPrivateHost(host: string): boolean {
  const value = host.trim().toLowerCase().replace(/^\[|\]$/g, "");
  if (!value) return false;
  if (value === "localhost" || value.endsWith(".localhost") || value.endsWith(".local") || value.endsWith(".internal")) {
    return true;
  }
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(value)) return isPrivateIpv4(value);
  if (value.includes(":")) return isPrivateIpv6(value);
  return false;
}

export function isPrivateTarget(input: string): boolean {
  return isPrivateHost(parseTarget(input).host);
}

export function isPrivateRange(input: string): boolean {
  const token = input.split(/[,\s]+/).map((part) => part.trim()).find(Boolean);
  if (!token) return false;
  const host = token.includes("/") ? token.split("/")[0] : token;
  return isPrivateHost(host);
}
