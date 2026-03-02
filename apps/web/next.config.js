/** @type {import('next').NextConfig} */
const nextConfig = {
  transpilePackages: ['@meritum/shared'],
  webpack: (config) => {
    // Resolve .js imports to .ts files in the shared package (Node16 module resolution style)
    config.resolve.extensionAlias = {
      '.js': ['.ts', '.tsx', '.js', '.jsx'],
      '.mjs': ['.mts', '.mjs'],
      '.cjs': ['.cts', '.cjs'],
    };
    return config;
  },
};

module.exports = nextConfig;
