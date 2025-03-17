const assert = require('assert');
const { X509Hybrid } = require('./src/index');
const forge = require('node-forge');
const { ml_dsa65 } = require('@noble/post-quantum/ml-dsa');
const { randomBytes } = require('@noble/post-quantum/utils');
const fs = require('fs').promises;
const path = require('path');

// Mock file system operations for testing saveToFiles
const mockFs = {
    mkdir: async (dirPath, options) => {
        mockFs.createdDirectories.push(dirPath);
    },
    writeFile: async (filePath, data) => {
        mockFs.writtenFiles[filePath] = data;
    },
    readFile: async (filePath) => {
        if (mockFs.fileContents[filePath]) {
            return Buffer.from(mockFs.fileContents[filePath]);
        }
        throw new Error('File not found');
    },
    createdDirectories:{},
    writtenFiles: {},
    fileContents: {},
    reset: () => {
        mockFs.createdDirectories ={};
        mockFs.writtenFiles = {};
        mockFs.fileContents = {};
    }
};

describe('X509Hybrid', () => {
    let x509Hybrid;

    beforeEach(() => {
        x509Hybrid = new X509Hybrid();
        mockFs.reset();
        // Replace the actual fs with the mock
        Object.defineProperty(fs, 'mkdir', { value: mockFs.mkdir });
        Object.defineProperty(fs, 'writeFile', { value: mockFs.writeFile });
        Object.defineProperty(fs, 'readFile', { value: mockFs.readFile });
    });

    describe('Constructor', () => {
        it('should initialize with default options', () => {
            assert.strictEqual(x509Hybrid.options.commonName, 'localhost');
            assert.strictEqual(x509Hybrid.options.pqcAlgorithm, 'ml_dsa65');
        });

        it('should merge provided options with defaults', () => {
            const customOptions = { commonName: 'example.com', rsaKeySize: 4096, pqcAlgorithm: 'ml_dsa44' };
            const hybrid = new X509Hybrid(customOptions);
            assert.strictEqual(hybrid.options.commonName, 'example.com');
            assert.strictEqual(hybrid.options.rsaKeySize, 4096);
            assert.strictEqual(hybrid.options.pqcAlgorithm, 'ml_dsa44');
        });

        it('should throw an error for unsupported PQC algorithm', () => {
            assert.throws(() => new X509Hybrid({ pqcAlgorithm: 'unsupported_algorithm' }), Error, 'Unsupported PQC algorithm: unsupported_algorithm');
        });
    });

    describe('generateHybridX509Certificate', () => {
        it('should generate a self-signed certificate with RSA and ML-DSA keys', async () => {
            const certResult = await x509Hybrid.generateHybridX509Certificate({ commonName: 'test.com' });
            assert.ok(certResult.certificate.startsWith('-----BEGIN CERTIFICATE-----'));
            assert.ok(certResult.rsaPrivateKey.startsWith('-----BEGIN RSA PRIVATE KEY-----'));
            assert.ok(certResult.rsaPublicKey.startsWith('-----BEGIN PUBLIC KEY-----'));
            assert.ok(certResult.mlDsaPublicKey, 'ML-DSA public key should be present');
            assert.ok(certResult.mlDsaSecretKey, 'ML-DSA secret key should be present');
            assert.strictEqual(certResult.pqcAlgorithm, 'ml_dsa65');

            // Verify the presence of the PQC extension
            const cert = forge.pki.certificateFromPem(certResult.certificate);
            const extension = cert.getExtension({ id: '2.16.840.1.101.3.4.3.17' });
            assert.ok(extension, 'ML-DSA-65 extension should be in the certificate');
            assert.ok(extension.value.includes('ml_dsa65:'), 'Extension value should contain the algorithm and public key');
        });

        it('should use provided options for certificate generation', async () => {
            const commonName = 'another-test.org';
            const certResult = await x509Hybrid.generateHybridX509Certificate({ commonName });
            const cert = forge.pki.certificateFromPem(certResult.certificate);
            assert.strictEqual(cert.subject.getField('CN').value, commonName);
        });
    });

   

    describe('extractMlDsaPublicKey', () => {
        let generatedCert;

        beforeEach(async () => {
            generatedCert = await x509Hybrid.generateHybridX509Certificate();
        });

        it('should extract the ML-DSA public key from a certificate', () => {
            const publicKey = x509Hybrid.extractMlDsaPublicKey(generatedCert.certificate);
            assert.ok(publicKey instanceof Buffer);
            assert.strictEqual(publicKey.toString('base64'), generatedCert.mlDsaPublicKey);
        });

        it('should extract the ML-DSA public key for a specific algorithm if provided', async () => {
            const x509HybridWithAlgo = new X509Hybrid({ pqcAlgorithm: 'ml_dsa44' });
            const certResult = await x509HybridWithAlgo.generateHybridX509Certificate();
            const publicKey = x509HybridWithAlgo.extractMlDsaPublicKey(certResult.certificate, 'ml_dsa44');
            assert.ok(publicKey instanceof Buffer);
            const cert = forge.pki.certificateFromPem(certResult.certificate);
            const extension = cert.getExtension({ id: '2.16.840.1.101.3.4.3.16' });
            const [, base64Key] = extension.value.split(':');
            assert.strictEqual(publicKey.toString('base64'), base64Key);
        });

       
       
    });

    describe('hybridSignData', () => {
        let rsaPrivateKeyPem;
        let mlDsaSecretKeyBase64;
        let mlDsa;

        beforeEach(() => {
            const rsaKeys = forge.pki.rsa.generateKeyPair(2048);
            rsaPrivateKeyPem = forge.pki.privateKeyToPem(rsaKeys.privateKey);
            const seed = randomBytes(32);
            const mlDsaKeyPair = ml_dsa65.keygen(seed);
            mlDsaSecretKeyBase64 = Buffer.from(mlDsaKeyPair.secretKey).toString('base64');
            mlDsa = ml_dsa65;
        });

        it('should sign data using both RSA and ML-DSA', async () => {
            const data = 'test data to sign';
            const signatures = await x509Hybrid.hybridSignData(data, rsaPrivateKeyPem, mlDsaSecretKeyBase64);
            assert.ok(signatures.rsaSignature);
            assert.ok(signatures.pqSignature);
            assert.ok(signatures.combined);
            assert.strictEqual(signatures.pqcAlgorithm, 'ml_dsa65');

            // Basic validation of signature formats (not full verification here)
            assert.ok(Buffer.from(signatures.rsaSignature, 'base64').length > 0);
            assert.ok(Buffer.from(signatures.pqSignature, 'base64').length > 0);
            assert.ok(Buffer.from(signatures.combined, 'base64').length > 0);
        });

        it('should use the specified PQC algorithm for signing', async () => {
            const customHybrid = new X509Hybrid({ pqcAlgorithm: 'ml_dsa44' });
            const data = 'test data to sign';
            const seed = randomBytes(32);
            const mlDsaKeyPair = customHybrid.pqcAlgorithms['ml_dsa44'].keygen(seed);
            const customMlDsaSecretKeyBase64 = Buffer.from(mlDsaKeyPair.secretKey).toString('base64');
            const signatures = await customHybrid.hybridSignData(data, rsaPrivateKeyPem, customMlDsaSecretKeyBase64, 'ml_dsa44');
            assert.strictEqual(signatures.pqcAlgorithm, 'ml_dsa44');
        });

        it('should throw an error for unsupported PQC algorithm during signing', async () => {
            const data = 'test data to sign';
            await assert.rejects(
                x509Hybrid.hybridSignData(data, rsaPrivateKeyPem, mlDsaSecretKeyBase64, 'unsupported'),
                Error,
                'Unsupported PQC algorithm: unsupported'
            );
        });
    });

   

    describe('hybridVerifyData', () => {
        let generatedCert;
        let rsaPrivateKeyPem;
        let mlDsaSecretKeyBase64;
        let signatures;
        const dataToSign = 'data to verify';

        beforeEach(async () => {
            generatedCert = await x509Hybrid.generateHybridX509Certificate();
            rsaPrivateKeyPem = generatedCert.rsaPrivateKey;
            mlDsaSecretKeyBase64 = generatedCert.mlDsaSecretKey;
            signatures = await x509Hybrid.hybridSignData(dataToSign, rsaPrivateKeyPem, mlDsaSecretKeyBase64);
        });

        it('should verify valid RSA and ML-DSA signatures', async () => {
            const verificationResult = await x509Hybrid.hybridVerifyData(dataToSign, signatures, generatedCert.certificate);
            assert.strictEqual(verificationResult.rsaValid, true);
            assert.strictEqual(verificationResult.pqValid, true);
            assert.strictEqual(verificationResult.hybridValid, true);
            assert.strictEqual(verificationResult.algorithm, 'ml_dsa65');
        });

        it('should return false for hybridValid if RSA signature is invalid', async () => {
            const invalidRsaSignature = 'invalid';
            const invalidSignatures = { ...signatures, rsaSignature: invalidRsaSignature };
            const verificationResult = await x509Hybrid.hybridVerifyData(dataToSign, invalidSignatures, generatedCert.certificate);
            assert.strictEqual(verificationResult.rsaValid, false);
            assert.strictEqual(verificationResult.pqValid, true);
            assert.strictEqual(verificationResult.hybridValid, false);
        });

        it('should return false for hybridValid if ML-DSA signature is invalid', async () => {
            const invalidPqSignature = 'invalid';
            const invalidSignatures = { ...signatures, pqSignature: invalidPqSignature };
            const verificationResult = await x509Hybrid.hybridVerifyData(dataToSign, invalidSignatures, generatedCert.certificate);
            assert.strictEqual(verificationResult.rsaValid, true);
            assert.strictEqual(verificationResult.pqValid, false);
            assert.strictEqual(verificationResult.hybridValid, false);
        });

        it('should use the specified PQC algorithm for verification', async () => {
            const customHybrid = new X509Hybrid({ pqcAlgorithm: 'ml_dsa44' });
            const certResult = await customHybrid.generateHybridX509Certificate();
            const customSignatures = await customHybrid.hybridSignData(dataToSign, certResult.rsaPrivateKey, certResult.mlDsaSecretKey, 'ml_dsa44');
            const verificationResult = await customHybrid.hybridVerifyData(dataToSign, customSignatures, certResult.certificate, 'ml_dsa44');
            assert.strictEqual(verificationResult.algorithm, 'ml_dsa44');
            assert.strictEqual(verificationResult.hybridValid, true);
        });

        it('should handle no PQC algorithm specified', async () => {
            const verificationResult = await x509Hybrid.hybridVerifyData(dataToSign, { rsaSignature: signatures.rsaSignature, pqSignature: signatures.pqSignature }, generatedCert.certificate);
            assert.strictEqual(verificationResult.algorithm, 'ml_dsa65'); // Should default to instance option
            assert.strictEqual(verificationResult.hybridValid, true);
        });
    });

   
});
