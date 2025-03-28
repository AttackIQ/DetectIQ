/** @type {import('next').NextConfig} */
const nextConfig = {
  trailingSlash: true,
  experimental: {
    proxyTimeout: 600000, // 10 minutes
    serverComponentsExternalPackages: ['sharp'],
  },
  httpAgentOptions: {
    keepAlive: true,
  },
  staticPageGenerationTimeout: 600000, // 10 minutes
  async rewrites() {
    return [
      // API endpoints only - not the page itself
      {
        source: '/api/rules/:path*/',
        destination: 'http://127.0.0.1:8000/rules/:path*/',
        basePath: false
      },
      // Deploy endpoint
      {
        source: '/api/rules/:id/deploy/',
        destination: 'http://127.0.0.1:8000/rules/:id/deploy/',
        basePath: false
      },
      {
        source: '/api/app-config/:path*/',
        destination: 'http://127.0.0.1:8000/app-config/:path*/',
        basePath: false
      },
      {
        source: '/api/app-config/get-config/',
        destination: 'http://127.0.0.1:8000/app-config/get-config/',
        basePath: false
      },
      {
        source: '/api/app-config/update-config/',
        destination: 'http://127.0.0.1:8000/app-config/update-config/',
        basePath: false
      },
      {
        source: '/api/app-config/test-integration/',
        destination: 'http://127.0.0.1:8000/app-config/test-integration/',
        basePath: false
      },
      {
        source: '/api/rule-creator/:path*/',
        destination: 'http://127.0.0.1:8000/rule-creator/:path*/',
        basePath: false
      },
      // Other routes...
      {
        source: '/api/licenses/:type/',
        destination: '/api/licenses/:type/',
      },
      //{
      //  source: '/api/:path*/',
      //  destination: 'http://127.0.0.1:8000/api/:path*/',
      //  basePath: false
      //},
    ];
  },
  // Increase webpack buffer
  webpack: (config) => {
    config.performance = {
      ...config.performance,
      maxAssetSize: 5000000,
      maxEntrypointSize: 5000000,
    };
    return config;
  },
};

module.exports = nextConfig; 