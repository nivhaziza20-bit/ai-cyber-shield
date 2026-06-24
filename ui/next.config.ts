import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  reactStrictMode: true,

  async rewrites() {
    return [
      {
        source: "/api/backend/:path*",
        destination: `${process.env.BACKEND_URL ?? "http://localhost:8000"}/:path*`,
      },
    ];
  },

  experimental: {
    optimizePackageImports: ["lucide-react", "recharts", "reactflow"],
  },
};

export default nextConfig;
