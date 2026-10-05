import { defineConfig } from '@playwright/test'

const baseURL = 'http://127.0.0.1:4173/cloudthreat-atlas/'

export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: 'line',
  outputDir: '../output/playwright/test-results',
  use: {
    baseURL,
    browserName: 'chromium',
    headless: true,
    screenshot: 'off',
    trace: 'off',
    video: 'off',
    viewport: { width: 1440, height: 1000 },
  },
  webServer: {
    command: 'npm run preview -- --host 127.0.0.1 --port 4173 --base /cloudthreat-atlas/',
    url: baseURL,
    reuseExistingServer: !process.env.CI,
    timeout: 30_000,
  },
})
