import { expect, test } from '@playwright/test'

test('opens the static demo and explores evidence, a story, and a simulation', async ({ page }) => {
  await page.goto('./')

  await expect(page.locator('.brand')).toContainText('CLOUDTHREAT ATLAS')
  await expect(page.getByText('PUBLIC DEMO')).toBeVisible()

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
