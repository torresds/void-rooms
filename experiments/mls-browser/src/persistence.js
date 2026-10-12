const DATABASE_NAME = "void-rooms-mls-lab";
const STORE_NAME = "provider-snapshots";

function openDatabase() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DATABASE_NAME, 1);
    request.onupgradeneeded = () => {
      request.result.createObjectStore(STORE_NAME, { keyPath: "role" });
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

export async function saveSnapshot(role, expectedRevision, bytes, failWrite = false) {
  const database = await openDatabase();
  try {
    return await new Promise((resolve, reject) => {
      const transaction = database.transaction(STORE_NAME, "readwrite");
      const store = transaction.objectStore(STORE_NAME);
      const request = store.get(role);
      let failure;
      let nextRevision;

      request.onsuccess = () => {
        const current = request.result;
        const currentRevision = current?.revision ?? -1;
        if (currentRevision !== expectedRevision) {
          failure = new Error("revision conflict");
          transaction.abort();
          return;
        }
        if (failWrite) {
          failure = new Error("injected transaction abort");
          transaction.abort();
          return;
        }
        nextRevision = currentRevision + 1;
        store.put({ role, revision: nextRevision, bytes: new Uint8Array(bytes) });
      };
      request.onerror = () => {
        failure = request.error;
        transaction.abort();
      };
      transaction.oncomplete = () => resolve(nextRevision);
      transaction.onabort = () => reject(failure ?? transaction.error ?? new Error("transaction aborted"));
      transaction.onerror = () => {
        failure ??= transaction.error;
      };
    });
  } finally {
    database.close();
  }
}

export async function loadSnapshot(role) {
  const database = await openDatabase();
  try {
    return await new Promise((resolve, reject) => {
      const transaction = database.transaction(STORE_NAME, "readonly");
      const request = transaction.objectStore(STORE_NAME).get(role);
      request.onsuccess = () => resolve(request.result ?? null);
      request.onerror = () => reject(request.error);
    });
  } finally {
    database.close();
  }
}

export async function replaceSnapshot(role, bytes) {
  const database = await openDatabase();
  try {
    return await new Promise((resolve, reject) => {
      const transaction = database.transaction(STORE_NAME, "readwrite");
      const store = transaction.objectStore(STORE_NAME);
      const request = store.get(role);
      request.onsuccess = () => {
        const current = request.result;
        store.put({ role, revision: current?.revision ?? 0, bytes: new Uint8Array(bytes) });
      };
      transaction.oncomplete = resolve;
      transaction.onerror = () => reject(transaction.error);
      transaction.onabort = () => reject(transaction.error ?? new Error("replacement aborted"));
    });
  } finally {
    database.close();
  }
}

export async function clearSnapshots() {
  const database = await openDatabase();
  try {
    return await new Promise((resolve, reject) => {
      const transaction = database.transaction(STORE_NAME, "readwrite");
      transaction.objectStore(STORE_NAME).clear();
      transaction.oncomplete = resolve;
      transaction.onerror = () => reject(transaction.error);
      transaction.onabort = () => reject(transaction.error ?? new Error("clear aborted"));
    });
  } finally {
    database.close();
  }
}
