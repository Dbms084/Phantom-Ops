export async function generateUserKeyPair() {
  return await window.crypto.subtle.generateKey(
    {
      name: "ECDH",
      namedCurve: "P-256"
    },
    true,
    ["deriveKey"]
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