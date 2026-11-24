import { MOCK_MAX_DELAY, MOCK_MIN_DELAY } from "../config";

export function jitter(min = MOCK_MIN_DELAY, max = MOCK_MAX_DELAY): number {
  return Math.floor(min + Math.random() * (max - min));
}

export function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function mocked<T>(data: T, min?: number, max?: number): Promise<T> {
  return delay(jitter(min, max)).then(() => clone(data));
}

export function clone<T>(value: T): T {
  if (value === undefined || value === null) return value;
  return JSON.parse(JSON.stringify(value)) as T;
}

export function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return function () {
    a += 0x6d2b79f5;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export function randInt(min: number, max: number, rnd: () => number = Math.random): number {
  return Math.floor(rnd() * (max - min + 1)) + min;
}

export function pick<T>(arr: readonly T[], rnd: () => number = Math.random): T {
  return arr[Math.floor(rnd() * arr.length)];
}

export function randomSerialNumber(rnd: () => number): string {
  const chars = "0123456789ABCDEF";
  let out = "";
  for (let i = 0; i < 32; i++) {
    out += chars[Math.floor(rnd() * 16)];
    if (i % 4 === 3 && i < 31) out += "";
  }
  return out.replace(/(.{8})(?=.)/g, "$1:");
}

export function fingerprint(bytes: string): string {
  return bytes.replace(/(.{2})(?=.)/g, "$1:").toLowerCase();
}

export function randomIp(rnd: () => number, internal: boolean): string {
  if (internal) {
    const third = Math.floor(rnd() * 255);
    const fourth = Math.floor(rnd() * 254) + 1;
    return `10.0.${third}.${fourth}`;
  }
  return `${randInt(104, 216, rnd)}.${randInt(0, 255, rnd)}.${randInt(0, 255, rnd)}.${randInt(1, 254, rnd)}`;
}

export function uuid(prefix = "id"): string {
  return `${prefix}_${Math.random().toString(36).slice(2, 8)}${Date.now().toString(36).slice(-4)}`;
}
