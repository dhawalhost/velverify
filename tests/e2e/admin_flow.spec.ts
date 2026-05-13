import { test, expect } from '@playwright/test';

test('Complete Admin Flow: Workspace Setup & User Provisioning', async ({ page }) => {
  test.setTimeout(60000);
  const randomSuffix = Math.floor(Math.random() * 10000);
  const adminEmail = `admin_${randomSuffix}@example.com`;
  const adminPassword = 'AdminPassword123!';
  const companyName = `AdminCorp_${randomSuffix}`;

  // 1. Admin Signup Flow
  await page.goto('http://admin.wardseal.local/signup');
  await expect(page.getByText('Create your account')).toBeVisible();

  await page.fill('#companyName', companyName);
  await page.fill('#email', adminEmail);
  await page.fill('#password', adminPassword);
  await page.click('button[type="submit"]');

  // Wait for Dashboard
  await page.waitForURL('**/dashboard');
  await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible();
  
  // 2. Provision a New SCIM Identity User
  await page.click('button:has-text("Add user")');
  await page.waitForURL('**/users/new');
  await expect(page.getByText('Core Information')).toBeVisible();

  const newUserName = `provisioned_${randomSuffix}@wardseal.io`;
  const newDisplayName = `Provisioned User ${randomSuffix}`;
  const newContactEmail = `contact_${randomSuffix}@wardseal.io`;

  // Fill User Info via placeholders
  await page.fill('input[placeholder="e.g. j.doe@wardseal.io"]', newUserName);
  await page.fill('input[placeholder="e.g. John Doe"]', newDisplayName);
  await page.fill('input[placeholder="e.g. john.doe@provider.com"]', newContactEmail);

  await page.click('button[type="submit"]');

  // Wait for redirection to User list
  await page.waitForURL('**/users');
  await expect(page.getByText(newContactEmail).first()).toBeVisible();
});
