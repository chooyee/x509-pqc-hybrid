# x509-pqc-hybrid

A Node.js library for creating and managing hybrid X.509 certificates with traditional RSA and post-quantum ML-DSA algorithms.

[![npm version](https://img.shields.io/npm/v/x509-pqc-hybrid.svg)](https://www.npmjs.com/package/x509-pqc-hybrid)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Overview

`x509-pqc-hybrid` provides tools to create, sign, and verify X.509 certificates that combine traditional RSA cryptography with post-quantum ML-DSA algorithms. This hybrid approach offers protection against both classical and quantum computing threats.

## Features

- Generate hybrid X.509 certificates with RSA + ML-DSA algorithms
- Support for multiple ML-DSA variants (ML-DSA-44, ML-DSA-65, ML-DSA-87)
- Create dual signatures using both traditional and post-quantum keys
- Verify hybrid signatures for files and data
- Certificate and key management utilities
- Complete certificate creation with customizable attributes

## Installation

```bash
npm install x509-pqc-hybrid
```

## Usage

### Basic Example

```javascript
const { X509Hybrid } = require('x509-pqc-hybrid');

// Create a new hybrid certificate generator
const x509 = new X509Hybrid({
  commonName: 'example.com',
  organization: 'Example Corp',
  pqcAlgorithm: 'ml_dsa65'
});

async function generateCertificate() {
  try {
    // Generate a hybrid certificate
    const cert = await x509.generateHybridX509Certificate();
    
    // Save certificate files
    await x509.saveToFiles(
      './certs/',
      cert.certificate,
      cert.rsaPrivateKey,
      cert.rsaPublicKey,
      cert.mlDsaPublicKey,
      cert.mlDsaSecretKey
    );
    
    console.log('Certificate generated successfully!');
  } catch (error) {
    console.error('Certificate generation failed:', error);
  }
}

generateCertificate();
```

### Signing and Verifying Data

```javascript
const { X509Hybrid } = require('x509-pqc-hybrid');
const fs = require('fs').promises;

async function signAndVerify() {
  const x509 = new X509Hybrid();
  
  try {
    // Load your certificate and keys
    const certificate = await fs.readFile('./certs/certificate.pem', 'utf8');
    const rsaPrivateKey = await fs.readFile('./certs/private.key', 'utf8');
    const mlDsaSecretKey = await fs.readFile('./certs/pq_secret.key', 'utf8');
    
    // Data to sign
    const data = 'Important message that needs post-quantum protection';
    
    // Sign the data
    const signatures = await x509.hybridSignData(
      data, 
      rsaPrivateKey,
      mlDsaSecretKey,
      'ml_dsa65'
    );
    
    console.log('Data signed successfully');
    
    // Verify the signatures
    const verificationResult = await x509.hybridVerifyData(
      data,
      signatures,
      certificate,
      'ml_dsa65'
    );
    
    console.log('Verification results:');
    console.log(`RSA signature valid: ${verificationResult.rsaValid}`);
    console.log(`PQ signature valid: ${verificationResult.pqValid}`);
    console.log(`Hybrid verification: ${verificationResult.hybridValid ? 'SUCCESS' : 'FAILED'}`);
    
  } catch (error) {
    console.error('Error:', error);
  }
}

signAndVerify();
```

### Signing and Verifying Files

```javascript
const { X509Hybrid } = require('x509-pqc-hybrid');
const fs = require('fs').promises;

async function signAndVerifyFile() {
  const x509 = new X509Hybrid();
  
  try {
    // Load your certificate and keys
    const certificate = await fs.readFile('./certs/certificate.pem', 'utf8');
    const rsaPrivateKey = await fs.readFile('./certs/private.key', 'utf8');
    const mlDsaSecretKey = await fs.readFile('./certs/pq_secret.key', 'utf8');
    
    // File to sign
    const filePath = './documents/important.pdf';
    
    // Sign the file
    const signatures = await x509.hybridSignFile(
      filePath, 
      rsaPrivateKey,
      mlDsaSecretKey,
      'ml_dsa65'
    );
    
    console.log('File signed successfully');
    
    // Verify the file signatures
    const verificationResult = await x509.hybridVerifyFile(
      filePath,
      signatures,
      certificate,
      'ml_dsa65'
    );
    
    console.log('Verification results:');
    console.log(`RSA signature valid: ${verificationResult.rsaValid}`);
    console.log(`PQ signature valid: ${verificationResult.pqValid}`);
    console.log(`Hybrid verification: ${verificationResult.hybridValid ? 'SUCCESS' : 'FAILED'}`);
    
  } catch (error) {
    console.error('Error:', error);
  }
}

signAndVerifyFile();
```

## API Reference

### `X509Hybrid`

#### Constructor

```javascript
const x509 = new X509Hybrid(options);
```

Options:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| commonName | string | 'localhost' | Common Name for the certificate |
| organization | string | 'Test Organization' | Organization name |
| organizationalUnit | string | 'IT Department' | Organizational unit |
| country | string | 'US' | Country code |
| state | string | 'State' | State or province |
| locality | string | 'City' | Locality or city |
| validityDays | number | 365 | Certificate validity in days |
| rsaKeySize | number | 2048 | Size of RSA key (2048, 4096, etc.) |
| pqcAlgorithm | string | 'ml_dsa65' | Post-quantum algorithm to use |

#### Methods

##### `generateHybridX509Certificate(options)`

Generates a hybrid X.509 certificate with RSA and post-quantum ML-DSA keys.

Returns: Promise resolving to an object containing certificate, keys, and PQ material.

##### `saveToFiles(basePath, certificate, rsaPrivateKey, rsaPublicKey, mlDsaPublicKey, mlDsaSecretKey)`

Saves certificate files to the specified directory.

Returns: Promise resolving to an object with file paths.

##### `extractMlDsaPublicKey(certificatePem, pqcAlgorithm)`

Extracts the ML-DSA public key from a hybrid certificate.

Returns: Buffer containing the ML-DSA public key or null if not found.

##### `hybridSignData(data, rsaPrivateKeyPem, mlDsaSecretKeyBase64, pqcAlgorithm)`

Signs data using both RSA and the selected post-quantum algorithm.

Returns: Promise resolving to an object with the hybrid signature.

##### `hybridSignFile(filePath, rsaPrivateKeyPem, mlDsaSecretKeyBase64, pqcAlgorithm)`

Signs a file using both RSA and the selected post-quantum algorithm.

Returns: Promise resolving to an object with the hybrid signature.

##### `hybridVerifyData(data, signatures, certificatePem, pqcAlgorithm)`

Verifies hybrid signatures against the original data.

Returns: Promise resolving to an object with verification results.

##### `hybridVerifyFile(filePath, signatures, certificatePem, pqcAlgorithm)`

Verifies hybrid signatures for a file.

Returns: Promise resolving to an object with verification results.

## Supported Post-Quantum Algorithms

| Algorithm | Description |
|-----------|-------------|
| ml_dsa44  | ML-DSA-44 (smaller key size, faster but less secure) |
| ml_dsa65  | ML-DSA-65 (medium key size, balanced performance and security) |
| ml_dsa87  | ML-DSA-87 (larger key size, higher security but slower) |

## Why Use Hybrid Certificates?

Post-quantum cryptography (PQC) is designed to be secure against attacks from quantum computers. However, many PQC algorithms are relatively new and haven't been subjected to the same level of cryptanalysis as traditional algorithms like RSA.

A hybrid approach provides:
1. Protection against both classical and quantum computing threats
2. Backward compatibility with existing systems
3. Defense-in-depth security strategy

## License

MIT