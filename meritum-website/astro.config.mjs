// @ts-check
import { defineConfig } from 'astro/config';
import tailwindcss from '@tailwindcss/vite';
import preact from '@astrojs/preact';
import sitemap from '@astrojs/sitemap';

export default defineConfig({
  site: 'https://meritum.ca',
  output: 'static',
  integrations: [preact(), sitemap()],
  vite: {
    plugins: [tailwindcss()],
  },
});
