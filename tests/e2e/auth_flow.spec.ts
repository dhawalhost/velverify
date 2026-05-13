import { test, expect } from '@playwright/test';

test('Complete Auth Flow: Registration, Login, and MFA Lifecycle', async ({ browser }) => {
  test.setTimeout(60000);
  const otplib = require('otplib');
  const randomSuffix = Math.floor(Math.random() * 10000);
  const testEmail = `testuser_${randomSuffix}@example.com`;
  const testPassword = 'Password123!';
  const companyName = `TestCorp_${randomSuffix}`;

  // 1. Registration
  const context1 = await browser.newContext();
  const page1 = await context1.newPage();

  await page1.goto('http://id.wardseal.local/signup');
  await expect(page1.getByText('Create your account')).toBeVisible();

  await page1.fill('#companyName', companyName);
  await page1.fill('#email', testEmail);
  await page1.fill('#password', testPassword);
  await page1.click('button[type="submit"]');

  await page1.waitForURL('**/profile');
  await expect(page1.getByText('Subject Attributes')).toBeVisible();
  await context1.close();

  // 2. Login & MFA Setup
  const context2 = await browser.newContext();
  const page2 = await context2.newPage();

  await page2.goto('http://id.wardseal.local/login');
  await expect(page2.getByText('Welcome back')).toBeVisible();

  // Step 1: Email
  await page2.fill('#email', testEmail);
  await page2.click('button[type="submit"]');

  // Step 2: Password
  await page2.waitForSelector('#password');
  await page2.fill('#password', testPassword);
  await page2.click('button[type="submit"]');

  // Step 3: MFA Setup
  await expect(page2.getByText('Setup MFA')).toBeVisible();

  const secretElement = await page2.waitForSelector('.font-mono');
  const secret = await secretElement.innerText();
  expect(secret).toBeTruthy();

  const totpCode = await otplib.generate({ secret });

  await page2.fill('input[placeholder="000 000"]', totpCode);
  await page2.click('button[type="submit"]');

  // Expect Profile page
  await page2.waitForURL('**/profile');
  await expect(page2.getByText('Subject Attributes')).toBeVisible();

  // 3. Password Rotation Flow
  await page2.fill('input[placeholder="Enter new entropy string..."]', 'NewPassword123!');
  await page2.click('button:has-text("Commit Rotation")');
  await expect(page2.getByText('PROFILE SECURITY UPDATED SUCCESSFULLY')).toBeVisible();

  // 4. MFA Lifecycle Management Flow
  await page2.goto('http://id.wardseal.local/mfa');
  await expect(page2.getByText('Profile Hardened')).toBeVisible();

  // Disable MFA
  page2.once('dialog', dialog => dialog.accept());
  await page2.click('button:has-text("Revert Hardening")');
  await expect(page2.getByText('Status: Dormant')).toBeVisible();

  // Re-enable MFA
  await page2.click('button:has-text("Initialize MFA Vector")');
  const newSecretElement = await page2.waitForSelector('.font-mono');
  const newSecret = await newSecretElement.innerText();
  expect(newSecret).toBeTruthy();

  const newTotpCode = await otplib.generate({ secret: newSecret });

  await page2.fill('input[placeholder="000 000"]', newTotpCode);
  await page2.click('button:has-text("Commit Protocol")');
  await expect(page2.getByText('Profile Hardened')).toBeVisible();

  await context2.close();
});
