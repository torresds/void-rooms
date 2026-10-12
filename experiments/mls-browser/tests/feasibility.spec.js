import { expect, test } from "@playwright/test";

async function openLab(page) {
  await page.goto("/");
  await expect(page.locator("#status")).toHaveText("WebAssembly module initialized");
}

async function startAndPersist(page) {
  return page.evaluate(async () => {
    const { BrowserMlsLab, saveSnapshot } = window.mlsLab;
    const lab = new BrowserMlsLab();
    lab.initialize();
    const aliceKey = Array.from(lab.alice_public_key());
    const bobKey = Array.from(lab.bob_public_key());
    await saveSnapshot("alice", -1, lab.snapshot_alice());
    await saveSnapshot("bob", -1, lab.snapshot_bob());
    return { aliceKey, bobKey, aliceEpoch: lab.alice_epoch(), bobEpoch: lab.bob_epoch() };
  });
}

async function restore(page, aliceKey, bobKey) {
  return page.evaluate(async ({ aliceKey, bobKey }) => {
    const { BrowserMlsLab, loadSnapshot } = window.mlsLab;
    const lab = new BrowserMlsLab();
    const alice = await loadSnapshot("alice");
    const bob = await loadSnapshot("bob");
    if (!alice || !bob) throw new Error("required snapshots are missing");
    lab.restore_alice(alice.bytes, new Uint8Array(aliceKey));
    lab.restore_bob(bob.bytes, new Uint8Array(bobKey));
    return {
      lab,
      aliceRevision: alice.revision,
      bobRevision: bob.revision,
      aliceEpoch: lab.alice_epoch(),
      bobEpoch: lab.bob_epoch(),
    };
  }, { aliceKey, bobKey });
}

test("runs MLS in browser and continues after a full runtime restart", async ({ page }) => {
  await openLab(page);
  const initial = await startAndPersist(page);
  expect(initial.aliceKey).toHaveLength(32);
  expect(initial.bobKey).toHaveLength(32);
  expect(initial.aliceEpoch).toBeGreaterThan(0);
  expect(initial.bobEpoch).toBe(initial.aliceEpoch);

  const firstExchange = await page.evaluate(async ({ aliceKey, bobKey }) => {
    const { BrowserMlsLab, saveSnapshot } = window.mlsLab;
    const lab = new BrowserMlsLab();
    const alice = await window.mlsLab.loadSnapshot("alice");
    const bob = await window.mlsLab.loadSnapshot("bob");
    lab.restore_alice(alice.bytes, new Uint8Array(aliceKey));
    lab.restore_bob(bob.bytes, new Uint8Array(bobKey));
    const message = lab.create_alice_message(new TextEncoder().encode("before restart"));
    const revision = await saveSnapshot("alice", alice.revision, lab.snapshot_alice());
    const plaintext = lab.receive_bob_message(message);
    await saveSnapshot("bob", bob.revision, lab.snapshot_bob());
    return { plaintext: new TextDecoder().decode(plaintext), revision };
  }, initial);
  expect(firstExchange.plaintext).toBe("before restart");
  expect(firstExchange.revision).toBe(1);

  await page.reload();
  await expect(page.locator("#status")).toHaveText("WebAssembly module initialized");
  const recovered = await page.evaluate(async ({ aliceKey, bobKey }) => {
    const { BrowserMlsLab, loadSnapshot, saveSnapshot } = window.mlsLab;
    const lab = new BrowserMlsLab();
    const alice = await loadSnapshot("alice");
    const bob = await loadSnapshot("bob");
    lab.restore_alice(alice.bytes, new Uint8Array(aliceKey));
    lab.restore_bob(bob.bytes, new Uint8Array(bobKey));
    const before = [lab.alice_epoch(), lab.bob_epoch()];
    const message = lab.create_bob_message(new TextEncoder().encode("after restart"));
    const bobRevision = await saveSnapshot("bob", bob.revision, lab.snapshot_bob());
    const plaintext = lab.receive_alice_message(message);
    const aliceRevision = await saveSnapshot("alice", alice.revision, lab.snapshot_alice());
    return {
      before,
      after: [lab.alice_epoch(), lab.bob_epoch()],
      plaintext: new TextDecoder().decode(plaintext),
      aliceRevision,
      bobRevision,
    };
  }, initial);
  expect(recovered.before).toEqual([initial.aliceEpoch, initial.bobEpoch]);
  expect(recovered.after).toEqual(recovered.before);
  expect(recovered.plaintext).toBe("after restart");
  expect(recovered.aliceRevision).toBe(2);
  expect(recovered.bobRevision).toBe(2);

  const tamperRejected = await page.evaluate(async ({ aliceKey, bobKey }) => {
    const { BrowserMlsLab, loadSnapshot } = window.mlsLab;
    const alice = await loadSnapshot("alice");
    const bob = await loadSnapshot("bob");
    const lab = new BrowserMlsLab();
    lab.restore_alice(alice.bytes, new Uint8Array(aliceKey));
    lab.restore_bob(bob.bytes, new Uint8Array(bobKey));
    const message = lab.create_alice_message(new TextEncoder().encode("tamper"));
    message[message.length - 1] ^= 1;
    try {
      lab.receive_bob_message(message);
      return false;
    } catch {
      return true;
    }
  }, initial);
  expect(tamperRejected).toBe(true);
});

test("recovers the last committed state after an IndexedDB transaction abort", async ({ page }) => {
  await openLab(page);
  const identity = await startAndPersist(page);
  const outcome = await page.evaluate(async ({ aliceKey }) => {
    const { BrowserMlsLab, loadSnapshot, saveSnapshot } = window.mlsLab;
    const lab = new BrowserMlsLab();
    const alice = await loadSnapshot("alice");
    const before = Array.from(alice.bytes);
    lab.restore_alice(alice.bytes, new Uint8Array(aliceKey));
    lab.create_alice_message(new TextEncoder().encode("must not be delivered"));
    let aborted = false;
    try {
      await saveSnapshot("alice", alice.revision, lab.snapshot_alice(), true);
    } catch (error) {
      aborted = error.message === "injected transaction abort";
    }
    const current = await loadSnapshot("alice");
    return { aborted, unchanged: JSON.stringify(Array.from(current.bytes)) === JSON.stringify(before) };
  }, identity);
  expect(outcome).toEqual({ aborted: true, unchanged: true });

  await page.reload();
  await expect(page.locator("#status")).toHaveText("WebAssembly module initialized");
  const recovered = await page.evaluate(async ({ aliceKey, bobKey }) => {
    const { BrowserMlsLab, loadSnapshot, saveSnapshot } = window.mlsLab;
    const lab = new BrowserMlsLab();
    const alice = await loadSnapshot("alice");
    const bob = await loadSnapshot("bob");
    lab.restore_alice(alice.bytes, new Uint8Array(aliceKey));
    lab.restore_bob(bob.bytes, new Uint8Array(bobKey));
    const message = lab.create_alice_message(new TextEncoder().encode("recovered"));
    const revision = await saveSnapshot("alice", alice.revision, lab.snapshot_alice());
    const plaintext = lab.receive_bob_message(message);
    await saveSnapshot("bob", bob.revision, lab.snapshot_bob());
    return { revision, plaintext: new TextDecoder().decode(plaintext) };
  }, identity);
  expect(recovered).toEqual({ revision: 1, plaintext: "recovered" });
});

test("rejects corrupted and substituted provider snapshots", async ({ page }) => {
  await openLab(page);
  const identity = await startAndPersist(page);
  const outcome = await page.evaluate(async ({ aliceKey, bobKey }) => {
    const { BrowserMlsLab, loadSnapshot, replaceSnapshot } = window.mlsLab;
    const alice = await loadSnapshot("alice");
    const bob = await loadSnapshot("bob");
    const corrupt = new Uint8Array(alice.bytes.slice(0, alice.bytes.length - 1));
    await replaceSnapshot("alice", corrupt);
    const corruptLab = new BrowserMlsLab();
    let corruptionRejected = false;
    try {
      corruptLab.restore_alice(corrupt, new Uint8Array(aliceKey));
    } catch {
      corruptionRejected = true;
    }
    await replaceSnapshot("alice", bob.bytes);
    const substitutedLab = new BrowserMlsLab();
    let substitutionRejected = false;
    try {
      substitutedLab.restore_alice(bob.bytes, new Uint8Array(aliceKey));
    } catch {
      substitutionRejected = true;
    }
    await replaceSnapshot("alice", alice.bytes);
    const validLab = new BrowserMlsLab();
    validLab.restore_alice(alice.bytes, new Uint8Array(aliceKey));
    validLab.restore_bob(bob.bytes, new Uint8Array(bobKey));
    return { corruptionRejected, substitutionRejected, epoch: validLab.alice_epoch() };
  }, identity);
  expect(outcome.corruptionRejected).toBe(true);
  expect(outcome.substitutionRejected).toBe(true);
  expect(outcome.epoch).toBe(identity.aliceEpoch);
});

test("allows only one concurrent tab to commit a revision", async ({ page }) => {
  await openLab(page);
  const identity = await startAndPersist(page);
  const secondPage = await page.context().newPage();
  await openLab(secondPage);

  const prepared = await Promise.all([page, secondPage].map((tab, index) => tab.evaluate(async ({ index, aliceKey, bobKey }) => {
    const { BrowserMlsLab, loadSnapshot } = window.mlsLab;
    const alice = await loadSnapshot("alice");
    const bob = await loadSnapshot("bob");
    const lab = new BrowserMlsLab();
    lab.restore_alice(alice.bytes, new Uint8Array(aliceKey));
    if (index === 0) lab.restore_bob(bob.bytes, new Uint8Array(bobKey));
    const message = lab.create_alice_message(new TextEncoder().encode(`tab-${index}`));
    return { message: Array.from(message), snapshot: Array.from(lab.snapshot_alice()), revision: alice.revision };
  }, { index, aliceKey: identity.aliceKey, bobKey: identity.bobKey })));

  const commits = await Promise.all([page, secondPage].map((tab, index) => tab.evaluate(async ({ index, snapshot, revision }) => {
    try {
      const nextRevision = await window.mlsLab.saveSnapshot("alice", revision, new Uint8Array(snapshot));
      return { index, committed: true, nextRevision };
    } catch (error) {
      return { index, committed: false, error: error.message };
    }
  }, { index, snapshot: prepared[index].snapshot, revision: prepared[index].revision })));
  expect(commits.filter((commit) => commit.committed)).toHaveLength(1);
  expect(commits.filter((commit) => commit.error === "revision conflict")).toHaveLength(1);
  expect(commits.find((commit) => commit.committed).nextRevision).toBe(1);

  const winner = commits.find((commit) => commit.committed).index;
  const accepted = await page.evaluate(async ({ encoded, aliceKey, bobKey }) => {
    const { BrowserMlsLab, loadSnapshot, saveSnapshot } = window.mlsLab;
    const alice = await loadSnapshot("alice");
    const bob = await loadSnapshot("bob");
    const lab = new BrowserMlsLab();
    lab.restore_alice(alice.bytes, new Uint8Array(aliceKey));
    lab.restore_bob(bob.bytes, new Uint8Array(bobKey));
    const plaintext = lab.receive_bob_message(new Uint8Array(encoded));
    await saveSnapshot("bob", bob.revision, lab.snapshot_bob());
    return new TextDecoder().decode(plaintext);
  }, { encoded: prepared[winner].message, ...identity });
  expect(accepted).toBe(`tab-${winner}`);
});
