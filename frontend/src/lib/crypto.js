export async function generateUserKeyPair() {
  return await window.crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: "SHA-256"
    },
    true,
    ["encrypt", "decrypt"]
  );
}

export async function exportPublicKey(publicKey) {
  const exported = await window.crypto.subtle.exportKey(
    "spki",
    publicKey
  );

  return btoa(
    String.fromCharCode(...new Uint8Array(exported))
  );
}

export async function exportPrivateKey(privateKey) {
  const exported = await window.crypto.subtle.exportKey(
    "pkcs8",
    privateKey
  );

  return btoa(
    String.fromCharCode(...new Uint8Array(exported))
  );
}

export async function generateProjectKey() {
  return await window.crypto.subtle.generateKey(
    {
      name: "AES-GCM",
      length: 256
    },
    true,
    ["encrypt", "decrypt"]
  );
}

export async function exportProjectKey(projectKey) {
  const exported = await window.crypto.subtle.exportKey(
    "raw",
    projectKey
  );

  return btoa(
    String.fromCharCode(...new Uint8Array(exported))
  );
}

export async function importPublicKey(publicKeyString) {
  const binaryDer = Uint8Array.from(
    atob(publicKeyString),
    c => c.charCodeAt(0)
  );

  return await window.crypto.subtle.importKey(
    "spki",
    binaryDer.buffer,
    {
      name: "RSA-OAEP",
      hash: "SHA-256"
    },
    true,
    ["encrypt"]
  );
}

export async function importPrivateKey(privateKeyString) {
  const binaryDer = Uint8Array.from(
    atob(privateKeyString),
    c => c.charCodeAt(0)
  );

  return await window.crypto.subtle.importKey(
    "pkcs8",
    binaryDer.buffer,
    {
      name: "RSA-OAEP",
      hash: "SHA-256"
    },
    true,
    ["decrypt"]
  );
}

export async function encryptProjectKey(
  projectKeyString,
  publicKey
) {
  const encoded = new TextEncoder().encode(
    projectKeyString
  );

  const encrypted =
    await window.crypto.subtle.encrypt(
      {
        name: "RSA-OAEP"
      },
      publicKey,
      encoded
    );

  return btoa(
    String.fromCharCode(
      ...new Uint8Array(encrypted)
    )
  );
}

export async function decryptProjectKey(
  encryptedKey,
  privateKey
) {
  const encryptedBytes = Uint8Array.from(
    atob(encryptedKey),
    c => c.charCodeAt(0)
  );

  const decrypted =
    await window.crypto.subtle.decrypt(
      {
        name: "RSA-OAEP"
      },
      privateKey,
      encryptedBytes
    );

  return new TextDecoder().decode(
    decrypted
  );
}

export async function encryptMessage(message, projectKey) {
  const iv = window.crypto.getRandomValues(
    new Uint8Array(12)
  );

  const encoded = new TextEncoder().encode(message);

  const encrypted =
    await window.crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv
      },
      projectKey,
      encoded
    );

  return {
    ciphertext: btoa(
      String.fromCharCode(
        ...new Uint8Array(encrypted)
      )
    ),
    iv: btoa(
      String.fromCharCode(...iv)
    )
  };
}

export async function decryptMessage(
  ciphertext,
  iv,
  projectKey
) {
  const encryptedBytes = Uint8Array.from(
    atob(ciphertext),
    c => c.charCodeAt(0)
  );

  const ivBytes = Uint8Array.from(
    atob(iv),
    c => c.charCodeAt(0)
  );

  const decrypted =
    await window.crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: ivBytes
      },
      projectKey,
      encryptedBytes
    );

  return new TextDecoder().decode(
    decrypted
  );
}

export async function importProjectKey(projectKeyString) {
  const binaryKey = Uint8Array.from(
    atob(projectKeyString),
    c => c.charCodeAt(0)
  );

  return await window.crypto.subtle.importKey(
    "raw",
    binaryKey,
    {
      name: "AES-GCM"
    },
    true,
    ["encrypt", "decrypt"]
  );
}