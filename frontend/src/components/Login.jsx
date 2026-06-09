import React, { useState } from 'react';
import axios from 'axios';
import {
  generateUserKeyPair,
  exportPublicKey,
  exportPrivateKey
} from "../lib/crypto";




const API_URL = 'http://localhost:8000';

function Login({ onLogin }) {
  const [username, setUsername] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
  e.preventDefault();

  const trimmedUsername = username.trim();

  if (!trimmedUsername) return;

  setLoading(true);

  try {
    // Generate cryptographic identity
    const keyPair = await generateUserKeyPair();

    const publicKey = await exportPublicKey(
      keyPair.publicKey
    );

    const privateKey = await exportPrivateKey(
      keyPair.privateKey
    );


    // Store private key ONLY in browser
    localStorage.setItem(
      `private_key_${trimmedUsername}`,
      privateKey
    );

    // Send username + public key to backend
    const response = await axios.post(
      `${API_URL}/users/`,
      {
        username: trimmedUsername,
        public_key: publicKey
      }
    );

    onLogin(response.data);
  } catch (error) {
    console.error("Login failed", error);

    if (error.response) {
      console.error(
        "Backend Error:",
        error.response.data
      );
    }

    alert("Failed to login. Please try again.");
  } finally {
    setLoading(false);
  }
};

  return (
    <div className="login-container">
      <div className="login-card" style={{ border: '1px solid var(--accent-color)' }}>
        <h1 style={{ color: 'var(--accent-color)', WebkitBackgroundClip: 'unset', WebkitTextFillColor: 'unset', background: 'none' }}>SECURE LOGIN</h1>
        <p>Enter clearance credentials to access operations</p>
        <form onSubmit={handleSubmit} className="input-group">
          <input
            type="text"
            placeholder="Operator ID (Username)"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            disabled={loading}
            autoFocus
            style={{ fontFamily: 'inherit' }}
          />
          <button type="submit" disabled={loading || !username.trim()} style={{ textTransform: 'uppercase', letterSpacing: '2px' }}>
            {loading ? 'Authenticating...' : 'Authorize'}
          </button>
        </form>
      </div>
    </div>
  );
}

export default Login;
