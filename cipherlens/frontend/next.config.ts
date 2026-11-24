import type { NextConfig } from "next";
import { PHASE_DEVELOPMENT_SERVER } from "next/constants";

const API_TARGET = process.env.NEXT_PUBLIC_API_PROXY_TARGET ?? "http://127.0.0.1:8000";

const nextConfig: NextConfig = {
  allowedDevOrigins: ["127.0.0.1", "192.168.56.1"],
  async rewrites() {
    return [
      {
        source: "/api/:path*",
        destination: `${API_TARGET}/api/:path*`,
      },
    ];
  },
};

export default function config(phase: string): NextConfig {
  if (phase === PHASE_DEVELOPMENT_SERVER) {
    return { ...nextConfig, experimental: { proxyTimeout: 240_000 } };
  }
  return nextConfig;
}
