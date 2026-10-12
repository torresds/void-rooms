const DATABASE_NAME = "void-rooms-device-vault";
const STORE_NAME = "vaults";
const VAULT_KEY = "local-device";

function openDatabase() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DATABASE_NAME, 1);
    request.onupgradeneeded = () => request.result.createObjectStore(STORE_NAME);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

export async function loadVault() {
  const database = await openDatabase();
  try {
    return await new Promise((resolve, reject) => {
      const transaction = database.transaction(STORE_NAME, "readonly");
      const request = transaction.objectStore(STORE_NAME).get(VAULT_KEY);
      request.onsuccess = () => {
        const record = request.result;
        resolve(record ? { revision: record.revision, bytes: new Uint8Array(record.bytes) } : null);
      };
      request.onerror = () => reject(request.error);
    });
  } finally {
    database.close();
  }
}

export async function saveVault(expectedRevision, bytes, failBeforeCommit = false) {
  const database = await openDatabase();
  try {
    return await new Promise((resolve, reject) => {
      const transaction = database.transaction(STORE_NAME, "readwrite");
      const store = transaction.objectStore(STORE_NAME);
      const request = store.get(VAULT_KEY);
      let failure;
      let revision;
      request.onsuccess = () => {
        const current = request.result;
        const currentRevision = current?.revision ?? -1;
        if (currentRevision !== expectedRevision) {
          failure = new Error("vault revision conflict");
          transaction.abort();
          return;
        }
        if (failBeforeCommit) {
          failure = new Error("injected vault transaction abort");
          transaction.abort();
          return;
        }
        revision = currentRevision + 1;
        store.put({ revision, bytes: new Uint8Array(bytes) }, VAULT_KEY);
      };
      request.onerror = () => {
        failure = request.error;
        transaction.abort();
      };
      transaction.oncomplete = () => resolve(revision);
      transaction.onabort = () => reject(failure ?? transaction.error ?? new Error("vault transaction aborted"));
      transaction.onerror = () => {
        failure ??= transaction.error;
      };
    });
  } finally {
    database.close();
  }
}

export async function clearVault() {
  const database = await openDatabase();
  try {
    return await new Promise((resolve, reject) => {
      const transaction = database.transaction(STORE_NAME, "readwrite");
      transaction.objectStore(STORE_NAME).delete(VAULT_KEY);
      transaction.oncomplete = resolve;
      transaction.onerror = () => reject(transaction.error);
      transaction.onabort = () => reject(transaction.error ?? new Error("vault deletion aborted"));
    });
  } finally {
    database.close();
  }
}
