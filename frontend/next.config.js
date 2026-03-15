/** @type {import('next').NextConfig} */
const apiUrl = process.env.API_URL || "http://localhost:8000";
const nextConfig = {
  output: "standalone",
  async rewrites() {
    return [
      { source: "/api/:path*", destination: `${apiUrl}/api/:path*` },
      { source: "/ws/:path*", destination: `${apiUrl}/ws/:path*` },
    ];
  },
};
module.exports = nextConfig;
