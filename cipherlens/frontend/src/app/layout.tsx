import type { Metadata, Viewport } from "next";
import "./globals.css";
import { Providers } from "@/components/providers";

export const dynamic = "force-dynamic";

export const viewport: Viewport = { themeColor: "#08264a", colorScheme: "dark" };

export const metadata: Metadata = {
  title: "CipherLens",
  description:
    "TLS security posture monitoring, certificate inventory, network discovery and proactive alerts for security operations.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark h-full antialiased">
      <body className="min-h-full">
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
