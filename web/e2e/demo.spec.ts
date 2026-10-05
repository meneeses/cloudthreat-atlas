import { expect, test } from '@playwright/test'

test('opens the static demo and explores evidence, a story, and a simulation', async ({ page }) => {
  await page.goto('./')

  await expect(page.locator('.brand')).toContainText('CLOUDTHREAT ATLAS')
  await expect(page.getByText('PUBLIC DEMO')).toBeVisible()
  await expect(page.getByRole('button', { name: 'Scan Azure' })).toHaveCount(0)

  await page.getByRole('button', { name: 'Open intelligence panel' }).click()
  await expect(page.getByText('TRIAGE', { exact: true })).toHaveCount(0)
  const finding = page
    .locator('.finding-card')
    .filter({ hasText: 'Pipeline credential grants production Owner control' })
  await expect(finding).toBeVisible()
  await finding.getByText('Evidence & remediation').click()
  await expect(finding.getByText('RECOMMENDED FIX')).toBeVisible()
  await finding.getByRole('button', { name: /Security Platform Pipeline/ }).click()
  await expect(page.getByRole('heading', { name: 'Security Platform Pipeline' })).toBeVisible()

  const storyLauncher = page.getByRole('region', { name: 'Attack path stories' })
  await storyLauncher.getByRole('button').first().click()
  const story = page.getByRole('region', { name: /Story mode:/ })
  await expect(story.getByText('Step 1 of 5')).toBeVisible()
  await story.getByRole('button', { name: 'Next step' }).click()
  await expect(story.getByText('Step 2 of 5')).toBeVisible()
  await story.getByRole('button', { name: 'Exit story' }).click()

  await page
    .getByLabel('Choose a remediation simulation')
    .selectOption('sim-scope-vault-access')
  const simulation = page.locator('.simulation-result')
  await expect(simulation.getByText('RISK SCORE')).toBeVisible()
  await expect(simulation.getByText('80')).toBeVisible()
  await expect(simulation.getByText('1', { exact: true })).toBeVisible()
})

test('supports keyboard search and the mobile filter sheet', async ({ page }) => {
  await page.goto('./')

  const search = page.getByRole('searchbox', { name: 'Search resources' })
  await expect(search).toBeVisible()
  await page.keyboard.press('/')
  await expect(search).toBeFocused()
  await search.fill('Clinical API')
  await expect(page.getByText('2/13 assets')).toBeVisible()

  await page.setViewportSize({ width: 390, height: 844 })
  await page.getByRole('button', { name: /Filters/ }).click()
  const sheet = page.getByRole('dialog', { name: 'Graph filters' })
  await expect(sheet).toBeVisible()
  await sheet.getByRole('button', { name: 'critical' }).click()
  await page.keyboard.press('Escape')
  await expect(sheet).toBeHidden()
})
