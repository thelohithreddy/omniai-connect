import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  reactStrictMode: true,
  // Emits .next/standalone — a self-contained server bundle with only the traced
  // production dependencies. infra/docker/web.Dockerfile's `prod` stage copies it;
  // without this flag that directory is never produced and the image build fails.
  output: "standalone",
};

export default nextConfig;
