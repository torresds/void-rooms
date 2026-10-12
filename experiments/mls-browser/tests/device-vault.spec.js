import { expect, test } from "@playwright/test";

async function openLab(page) {
  await page.goto("/");
  await expect(page.locator("#status")).toHaveText("WebAssembly module initialized");
}

test("creates an encrypted device identity and unlocks it after a page restart", async ({ page }) => {
  await openLab(page);
  const saved = await page.evaluate(async () => {
    const { BrowserDeviceIdentity, clearVault, loadVault, saveVault } = window.mlsLab;
    await clearVault();
    const identityBytes = new TextEncoder().encode("browser-local-device");
    const passphrase = "browser test passphrase";
    const identity = new BrowserDeviceIdentity(identityBytes, passphrase);
    const vault = identity.seal(passphrase);
    await saveVault(-1, vault);
    const record = await loadVault();
    return {
      identity: Array.from(identity.identity()),
      publicKey: Array.from(identity.signing_public_key()),
      vault: Array.from(record.bytes),
      revision: record.revision,
      containsIdentity: new TextDecoder().decode(record.bytes).includes("browser-local-device"),
      containsPassphrase: new TextDecoder().decode(record.bytes).includes(passphrase),
    };
  });
  expect(saved.revision).toBe(0);
  expect(saved.vault.length).toBeGreaterThan(70);
  expect(saved.containsIdentity).toBe(false);
  expect(saved.containsPassphrase).toBe(false);

  await page.reload();
  await expect(page.locator("#status")).toHaveText("WebAssembly module initialized");
  const restored = await page.evaluate(async ({ vault }) => {
    const { BrowserDeviceIdentity, loadVault } = window.mlsLab;
    const stored = await loadVault();
    const identity = BrowserDeviceIdentity.unlock(stored.bytes, "browser test passphrase");
    let wrongPassphraseRejected = false;
    try {
      BrowserDeviceIdentity.unlock(stored.bytes, "incorrect passphrase");
    } catch {
      wrongPassphraseRejected = true;
    }
    const corrupted = new Uint8Array(vault);
    corrupted[corrupted.length - 1] ^= 1;
    let corruptedRecordRejected = false;
    try {
      BrowserDeviceIdentity.unlock(corrupted, "browser test passphrase");
    } catch {
      corruptedRecordRejected = true;
    }
    const foreign = new BrowserDeviceIdentity(new TextEncoder().encode("foreign-device"), "other passphrase");
    let substitutedRecordRejected = false;
    try {
      BrowserDeviceIdentity.unlock(foreign.seal("other passphrase"), "browser test passphrase");
    } catch {
      substitutedRecordRejected = true;
    }
    return {
      identity: Array.from(identity.identity()),
      publicKey: Array.from(identity.signing_public_key()),
      wrongPassphraseRejected,
      corruptedRecordRejected,
      substitutedRecordRejected,
    };
  }, { vault: saved.vault });
  expect(restored.identity).toEqual(saved.identity);
  expect(restored.publicKey).toEqual(saved.publicKey);
  expect(restored.wrongPassphraseRejected).toBe(true);
  expect(restored.corruptedRecordRejected).toBe(true);
  expect(restored.substitutedRecordRejected).toBe(true);
});

test("keeps the last committed vault after an IndexedDB transaction abort", async ({ page }) => {
  await openLab(page);
  const result = await page.evaluate(async () => {
    const { BrowserDeviceIdentity, clearVault, loadVault, saveVault } = window.mlsLab;
    await clearVault();
    const passphrase = "durable passphrase";
    const identity = new BrowserDeviceIdentity(new TextEncoder().encode("device-a"), passphrase);
    const firstVault = identity.seal(passphrase);
    await saveVault(-1, firstVault);
    const current = await loadVault();
    let aborted = false;
    try {
      await saveVault(current.revision, new Uint8Array([1, 2, 3]), true);
    } catch (error) {
      aborted = error.message === "injected vault transaction abort";
    }
    const after = await loadVault();
    return {
      aborted,
      sameRevision: after.revision === current.revision,
      sameBytes: JSON.stringify(Array.from(after.bytes)) === JSON.stringify(Array.from(current.bytes)),
    };
  });
  expect(result).toEqual({ aborted: true, sameRevision: true, sameBytes: true });
});

test("allows only one concurrent tab to commit a vault revision", async ({ page }) => {
  await openLab(page);
  await page.evaluate(async () => {
    const { clearVault, saveVault } = window.mlsLab;
    await clearVault();
    await saveVault(-1, new Uint8Array([10]));
  });
  const secondPage = await page.context().newPage();
  await openLab(secondPage);
  const results = await Promise.all([page, secondPage].map((tab, index) => tab.evaluate(async (index) => {
    const { loadVault, saveVault } = window.mlsLab;
    const record = await loadVault();
    await new Promise((resolve) => setTimeout(resolve, 10));
    try {
      const revision = await saveVault(record.revision, new Uint8Array([index + 20]));
      return { committed: true, revision };
    } catch (error) {
      return { committed: false, error: error.message };
    }
  }, index)));
  expect(results.filter((result) => result.committed)).toHaveLength(1);
  expect(results.filter((result) => result.error === "vault revision conflict")).toHaveLength(1);
});
