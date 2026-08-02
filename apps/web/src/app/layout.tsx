import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "OmniAI Connect",
  description: "Connect Any API. Use It From Any AI.",
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
