import type { Metadata } from "next";
import "./globals.css";
import AppShell from "@/components/AppShell";

export const metadata: Metadata = {
  title: "CHIMERA | Autonomous SOC & Deception Platform",
  description:
    "Next-Generation Autonomous Security Operations Center powered by Edge ML, Multi-Agent Crews, and Active Deception Honeypots.",
  icons: {
    icon: "/favicon.ico",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body className="bg-[#030303] text-[#f0f4f8] antialiased overflow-hidden selection:bg-[#00f0ff]/30 selection:text-white">
        <AppShell>{children}</AppShell>
      </body>
    </html>
  );
}
