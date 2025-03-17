/**
 * x509-pqc-hybrid - A library for creating and managing hybrid X.509 certificates 
 * with traditional RSA and post-quantum ML-DSA algorithms
 * 
 * @module x509hybrid
 */

const crypto = require('crypto');
const forge = require('node-forge');
const { ml_dsa44, ml_dsa65, ml_dsa87 } = require('@noble/post-quantum/ml-dsa');
const { randomBytes } = require('@noble/post-quantum/utils');
const fs = require('fs').promises;
const path = require('path');

/**
 * PQC Algorithm OIDs (Object Identifiers)
 * These are placeholder OIDs and should be replaced with official ones when available
 */
const PQC_OIDS = {
	'ml_dsa44': '2.16.840.1.101.3.4.3.16',
	'ml_dsa65': '2.16.840.1.101.3.4.3.17',
	'ml_dsa87': '2.16.840.1.101.3.4.3.18'
};

/**
 * Class for creating and managing hybrid X.509 certificates
 * combining traditional RSA with post-quantum ML-DSA algorithms
 */
class X509Hybrid {
	/**
	 * Constructor for X509Hybrid class
	 * @param {Object} options - Configuration options for the certificate generation
	 * @param {string} [options.commonName='localhost'] - Common Name for the certificate
	 * @param {string} [options.organization='Test Organization'] - Organization name
	 * @param {string} [options.organizationalUnit='IT Department'] - Organizational unit
	 * @param {string} [options.country='US'] - Country code
	 * @param {string} [options.state='State'] - State or province
	 * @param {string} [options.locality='City'] - Locality or city
	 * @param {number} [options.validityDays=365] - Certificate validity in days
	 * @param {number} [options.rsaKeySize=2048] - Size of RSA key (2048, 4096, etc.)
	 * @param {string} [options.pqcAlgorithm='ml_dsa65'] - Post-quantum algorithm to use
	 */
	constructor(options = {}) {
		// Default options
		this.defaultOptions = {
			commonName: 'localhost',
			organization: 'Test Organization',
			organizationalUnit: 'IT Department',
			country: 'US',
			state: 'State',
			locality: 'City',
			validityDays: 365,
			rsaKeySize: 2048,
			pqcAlgorithm: 'ml_dsa65'
		};

		// Merge provided options with defaults
		this.options = { ...this.defaultOptions, ...options };

		// Map algorithms to available implementations
		this.pqcAlgorithms = {
			'ml_dsa44': ml_dsa44,
			'ml_dsa65': ml_dsa65,
			'ml_dsa87': ml_dsa87
		};

		// Validate PQC algorithm
		if (!this.pqcAlgorithms[this.options.pqcAlgorithm]) {
			throw new Error(`Unsupported PQC algorithm: ${this.options.pqcAlgorithm}`);
		}
	}

	/**
	 * Generates a hybrid X.509 certificate with RSA and post-quantum ML-DSA keys
	 * 
	 * @param {Object} [options={}] - Configuration options for the certificate
	 * @returns {Promise<Object>} - Object containing certificate, keys, and PQ material
	 */
	async generateHybridX509Certificate(options = {}) {
		// Merge provided options with instance defaults
		const mergedOptions = { ...this.options, ...options };

		const {
			commonName,
			organization,
			organizationalUnit,
			country,
			state,
			locality,
			validityDays,
			rsaKeySize,
			pqcAlgorithm
		} = mergedOptions;

		try {
			// Generate traditional RSA keypair
			const rsaKeys = forge.pki.rsa.generateKeyPair(rsaKeySize);

			// Generate post-quantum ML-DSA keys
			const ml_dsa = this.pqcAlgorithms[pqcAlgorithm];
			const seed = randomBytes(32);
			const mlDsaKeyPair = ml_dsa.keygen(seed);
			const mlDsaPublicKey = mlDsaKeyPair.publicKey;
			const mlDsaSecretKey = mlDsaKeyPair.secretKey;

			// Create a new certificate
			const cert = forge.pki.createCertificate();

			// Set certificate fields
			cert.publicKey = rsaKeys.publicKey;
			cert.serialNumber = '01' + crypto.randomBytes(19).toString('hex'); // Random serial number

			// Set validity period
			const now = new Date();
			cert.validity.notBefore = now;
			const later = new Date();
			later.setDate(later.getDate() + validityDays);
			cert.validity.notAfter = later;

			// Set subject attributes
			const attrs = [
				{ name: 'commonName', value: commonName },
				{ name: 'organizationName', value: organization },
				{ name: 'organizationalUnitName', value: organizationalUnit },
				{ name: 'countryName', value: country },
				{ name: 'stateOrProvinceName', value: state },
				{ name: 'localityName', value: locality }
			];

			cert.setSubject(attrs);
			cert.setIssuer(attrs); // Self-signed, so issuer = subject

			// Encode the ML-DSA public key for inclusion in the certificate extensions
			const mlDsaPubKeyBase64 = Buffer.from(mlDsaPublicKey).toString('base64');

			// Get OID for the PQC algorithm
			const pqcOid = PQC_OIDS[pqcAlgorithm] || PQC_OIDS.ml_dsa65;

			// Set extensions including the post-quantum key
			cert.setExtensions([
				{
					name: 'basicConstraints',
					cA: true
				},
				{
					name: 'keyUsage',
					keyCertSign: true,
					digitalSignature: true,
					nonRepudiation: true,
					keyEncipherment: true,
					dataEncipherment: true
				},
				{
					name: 'subjectAltName',
					altNames: [
						{
							type: 2, // DNS
							value: commonName
						}
					]
				},
				{
					name: pqcAlgorithm,
					id: pqcOid,
					critical: false,
					value: `${pqcAlgorithm}:${mlDsaPubKeyBase64}`
				}
			]);

			// Self-sign the certificate with the RSA private key
			cert.sign(rsaKeys.privateKey, forge.md.sha256.create());

			// Convert to PEM format
			const certPem = forge.pki.certificateToPem(cert);
			const rsaPrivateKeyPem = forge.pki.privateKeyToPem(rsaKeys.privateKey);
			const rsaPublicKeyPem = forge.pki.publicKeyToPem(rsaKeys.publicKey);

			return {
				certificate: certPem,
				rsaPrivateKey: rsaPrivateKeyPem,
				rsaPublicKey: rsaPublicKeyPem,
				mlDsaPublicKey: mlDsaPubKeyBase64,
				mlDsaSecretKey: Buffer.from(mlDsaSecretKey).toString('base64'),
				pqcAlgorithm
			};
		} catch (error) {
			throw new Error(`Certificate generation failed: ${error.message}`);
		}
	}

	/**
	 * Saves certificate files to the specified directory
	 * 
	 * @param {string} [basePath='./'] - Directory path to save files
	 * @param {string} certificate - Certificate in PEM format
	 * @param {string} rsaPrivateKey - RSA private key in PEM format
	 * @param {string} rsaPublicKey - RSA public key in PEM format
	 * @param {string} [mlDsaPublicKey] - ML-DSA public key in base64 format
	 * @param {string} [mlDsaSecretKey] - ML-DSA secret key in base64 format
	 * @returns {Promise<Object>} - Object with file paths
	 */
	async saveToFiles(basePath = './', certificate, rsaPrivateKey, rsaPublicKey, mlDsaPublicKey, mlDsaSecretKey) {
		try {
			// Ensure trailing slash and directory exists
			basePath = path.resolve(basePath) + path.sep;
			await fs.mkdir(basePath, { recursive: true });

			const files = {
				certificatePath: path.join(basePath, 'certificate.pem'),
				rsaPrivateKeyPath: path.join(basePath, 'private.key'),
				rsaPublicKeyPath: path.join(basePath, 'public.key')
			};

			// Save primary files
			await fs.writeFile(files.rsaPrivateKeyPath, rsaPrivateKey);
			await fs.writeFile(files.rsaPublicKeyPath, rsaPublicKey);
			await fs.writeFile(files.certificatePath, certificate);

			// Optionally save PQ keys if provided
			if (mlDsaPublicKey) {
				files.mlDsaPublicKeyPath = path.join(basePath, 'pq_public.key');
				await fs.writeFile(files.mlDsaPublicKeyPath, mlDsaPublicKey);
			}

			if (mlDsaSecretKey) {
				files.mlDsaSecretKeyPath = path.join(basePath, 'pq_secret.key');
				await fs.writeFile(files.mlDsaSecretKeyPath, mlDsaSecretKey);
			}

			return files;
		} catch (err) {
			throw new Error(`Failed to save certificate files: ${err.message}`);
		}
	}

	/**
	 * Extracts the ML-DSA public key from a hybrid certificate
	 * 
	 * @param {string} certificatePem - Certificate in PEM format
	 * @param {string} [pqcAlgorithm] - The PQC algorithm to extract (if not specified, uses the options default)
	 * @returns {Buffer|null} - ML-DSA public key or null if not found
	 */
	extractMlDsaPublicKey(certificatePem, pqcAlgorithm) {
		try {
			const cert = forge.pki.certificateFromPem(certificatePem);
			const algorithm = pqcAlgorithm || this.options.pqcAlgorithm;
			const oid = PQC_OIDS[algorithm];

			// Look for the PQC extension by OID
			const mlDsaExtension = cert.getExtension({ id: oid });

			if (!mlDsaExtension) {
				throw new Error(`No ${algorithm} extension found in certificate`);
			}

			const [prefix, base64Key] = mlDsaExtension.value.split(':');

			if (!prefix || !base64Key) {
				throw new Error(`Invalid ${algorithm} key format in certificate`);
			}

			return Buffer.from(base64Key, 'base64');
		} catch (error) {
			console.error(`Error extracting ${pqcAlgorithm || this.options.pqcAlgorithm} key:`, error);
			return null;
		}
	}

	/**
	 * Signs data using both RSA and the selected post-quantum algorithm
	 * 
	 * @param {Buffer|string} data - The data to be signed
	 * @param {string} rsaPrivateKeyPem - RSA private key in PEM format
	 * @param {string} mlDsaSecretKeyBase64 - ML-DSA secret key in Base64 format
	 * @param {string} [pqcAlgorithm] - The post-quantum algorithm to use
	 * @returns {Promise<Object>} The hybrid signature
	 */
	async hybridSignData(data, rsaPrivateKeyPem, mlDsaSecretKeyBase64, pqcAlgorithm) {		
		try {
			return this._hybridSign(data, rsaPrivateKeyPem, mlDsaSecretKeyBase64, pqcAlgorithm);
		} catch (error) {
			throw new Error(`Hybrid signing failed: ${error.message}`);
		}
	}

	/**
	 * Signs a file using both RSA and the selected post-quantum algorithm
	 * 
	 * @param {string} filePath - Path to the file to sign
	 * @param {string} rsaPrivateKeyPem - RSA private key in PEM format
	 * @param {string} mlDsaSecretKeyBase64 - ML-DSA secret key in Base64 format
	 * @param {string} [pqcAlgorithm] - The post-quantum algorithm to use
	 * @returns {Promise<Object>} The hybrid signature
	 */
	async hybridSignFile(filePath, rsaPrivateKeyPem, mlDsaSecretKeyBase64, pqcAlgorithm) {		
		try {
			const fileData = await fs.readFile(filePath);
			return this._hybridSign(fileData, rsaPrivateKeyPem, mlDsaSecretKeyBase64, pqcAlgorithm);
		} catch (error) {
			throw new Error(`File signing failed: ${error.message}`);
		}
	}

	
	/**
	 * Signs data using both RSA and the selected post-quantum algorithm
	 * 
	 * @param {Buffer|string} data - The data to be signed
	 * @param {string} rsaPrivateKeyPem - RSA private key in PEM format
	 * @param {string} mlDsaSecretKeyBase64 - ML-DSA secret key in Base64 format
	 * @param {string} [pqcAlgorithm] - The post-quantum algorithm to use
	 * @returns {Promise<Object>} The hybrid signature
	 */
	async _hybridSign(data, rsaPrivateKeyPem, mlDsaSecretKeyBase64, pqcAlgorithm) {
		// Determine which algorithm to use (priority: parameter > instance default)
		const algorithm = pqcAlgorithm || this.options.pqcAlgorithm;

		if (!algorithm) {
			throw new Error('No PQC algorithm specified');
		}

		const ml_dsa = this.pqcAlgorithms[algorithm];
		if (!ml_dsa) {
			throw new Error(`Unsupported PQC algorithm: ${algorithm}`);
		}

		try {
			// Convert string data to Buffer if necessary
			const {dataBuffer, md} = this._prepDataType(data);

			// Traditional RSA signature
			const privateKey = forge.pki.privateKeyFromPem(rsaPrivateKeyPem);			
			const rsaSignature = privateKey.sign(md);

			// ML-DSA signature - post-quantum signature
			const mlDsaSecretKey = Buffer.from(mlDsaSecretKeyBase64, 'base64');
			const mlDsaSignature = await ml_dsa.sign(mlDsaSecretKey, dataBuffer);

			return {
				rsaSignature: forge.util.encode64(rsaSignature),
				pqSignature: Buffer.from(mlDsaSignature).toString('base64'),
				combined: Buffer.concat([
					Buffer.from(rsaSignature),
					Buffer.from(mlDsaSignature)
				]).toString('base64'),
				pqcAlgorithm: algorithm
			};
		} catch (error) {
			throw new Error(`Hybrid signing failed: ${error.message}`);
		}
	}


	/**
 * Verifies hybrid signatures against the original data
 * 
 * @param {Buffer|string} data - Original data that was signed
 * @param {Object} signatures - Object containing signatures from hybridSign
 * @param {string} signatures.rsaSignature - RSA signature in base64
 * @param {string} signatures.pqSignature - Post-quantum signature in base64
 * @param {string} signatures.pqcAlgorithm - Optional algorithm used for signing
 * @param {string} certificatePem - Certificate in PEM format
 * @param {string} [pqcAlgorithm] - The post-quantum algorithm to use (overrides signatures.pqcAlgorithm)
 * @returns {Promise<Object>} Verification results
 */
	async hybridVerifyData(data, signatures, certificatePem, pqcAlgorithm) {

		try {
			// Use the common verification logic
			return this._hybridVerify(data, signatures, certificatePem, pqcAlgorithm);
		} catch (error) {		
			return {
				rsaValid: false,
				pqValid: false,
				hybridValid: false,
				error: `File verification failed: ${error.message}`
			};
		}

	}

	/**
	 * Verifies hybrid signatures for a file
	 * 
	 * @param {string} filePath - Path to the original file
	 * @param {Object} signatures - Object containing signatures from hybridSignFile
	 * @param {string} signatures.rsaSignature - RSA signature in base64
	 * @param {string} signatures.pqSignature - Post-quantum signature in base64
	 * @param {string} signatures.pqcAlgorithm - Optional algorithm used for signing
	 * @param {string} certificatePem - Certificate in PEM format
	 * @param {string} [pqcAlgorithm] - The post-quantum algorithm to use (overrides signatures.pqcAlgorithm)
	 * @returns {Promise<Object>} Verification results
	 */
	async hybridVerifyFile(filePath, signatures, certificatePem, pqcAlgorithm) {
		try {
			// Read file asynchronously
			const fileData = await fs.readFile(filePath);

			// Use the common verification logic
			return this._hybridVerify(fileData, signatures, certificatePem, pqcAlgorithm);
		} catch (error) {
			// Handle file-specific errors
			if (error.code === 'ENOENT') {
				return {
					rsaValid: false,
					pqValid: false,
					hybridValid: false,
					error: `File not found: ${filePath}`
				};
			}

			return {
				rsaValid: false,
				pqValid: false,
				hybridValid: false,
				error: `File verification failed: ${error.message}`
			};
		}
	}
/**
	* Verifies hybrid signatures against the original data
 * 
 * @param {Buffer|string} data - Original data that was signed
 * @param {Object} signatures - Object containing signatures from hybridSign
 * @param {string} signatures.rsaSignature - RSA signature in base64
 * @param {string} signatures.pqSignature - Post-quantum signature in base64
 * @param {string} signatures.pqcAlgorithm - Optional algorithm used for signing
 * @param {string} certificatePem - Certificate in PEM format
 * @param {string} [pqcAlgorithm] - The post-quantum algorithm to use (overrides signatures.pqcAlgorithm)
 * @returns {Promise<Object>} Verification results
 */
	async _hybridVerify(data, signatures, certificatePem, pqcAlgorithm) {

		let errorMsg = '';
		// Determine which algorithm to use (priority: parameter > signature metadata > instance default)
		const algorithm = pqcAlgorithm || signatures.pqcAlgorithm || this.options.pqcAlgorithm;

		if (!algorithm) {
			throw new Error('No PQC algorithm specified');
		}

		const ml_dsa = this.pqcAlgorithms[algorithm];
		if (!ml_dsa) {
			throw new Error(`Unsupported PQC algorithm: ${algorithm}`);
		}

		const {dataBuffer, md} = this._prepDataType(data);

		// Extract keys from certificate
		const cert = forge.pki.certificateFromPem(certificatePem);
		const rsaPublicKey = cert.publicKey;
		const mlDsaPublicKey = this.extractMlDsaPublicKey(certificatePem, algorithm);

		if (!mlDsaPublicKey) {
			throw new Error(`No ${algorithm} public key found in certificate`);
		}

		// Verify RSA signature
		let isRsaValid = true;
		try{
			const rsaSignature = forge.util.decode64(signatures.rsaSignature);
			isRsaValid = rsaPublicKey.verify(md.digest().bytes(), rsaSignature);
		}
		catch(error)
		{
			errorMsg += `Verify RSA signature: ${error}\n`
			isRsaValid = false;
		}

		// Verify post-quantum signature
		let isPqValid = false;
		try{
			const pqSignature = Buffer.from(signatures.pqSignature, 'base64');
			isPqValid = await ml_dsa.verify(mlDsaPublicKey, dataBuffer, pqSignature);
		}
		catch(error)
		{
			errorMsg += `Verify post-quantum signature [${pqcAlgorithm}]: ${error}\n`
			isPqValid = false;
		}

		return {
			rsaValid: isRsaValid,
			pqValid: isPqValid,
			hybridValid: isRsaValid && isPqValid,
			algorithm,
			error: errorMsg
		};

	}

	_prepDataType(data){
		const md = forge.md.sha256.create();
		if (typeof data === 'string') { 
			const dataBuffer = Buffer.from(data);
			md.update(data, 'utf8');

			return {dataBuffer, md};
		}
		else
		{
			//data already in Buffer Array
			const dataBuffer = data;
			md.update(dataBuffer.toString('binary'));
			return {dataBuffer, md};
		}
		
	}
}


// Example of how to use the hybrid certificate system
async function example() {
	try {
		const ml_dsa = 'ml_dsa65';
		console.log('Generating hybrid X.509 certificate with RSA and ML-DSA-65...');

		const x509Hybrid = new X509Hybrid({
			rsaKeySize: 3072,
			pqcAlgorithm: ml_dsa
		});
		// Step 1: Generate a hybrid certificate
		const certResult = await x509Hybrid.generateHybridX509Certificate({
			commonName: 'chooyee.co',
			organization: 'Lee Corp',
			validityDays: 365,
			rsaKeySize: 3072 // Stronger RSA key
		});
		x509Hybrid.saveToFiles('./cert/', certResult.certificate, certResult.rsaPrivateKey, certResult.rsaPublicKey);
		console.log('Certificate generated successfully');
		console.log(`Certificate length: ${certResult.certificate.length} characters`);

		// Step 2: Sign File using both keys		
		const fileToSign = './uploads/test.txt';
		console.log('\nSigning data with hybrid approach...');
		let signatures = await x509Hybrid.hybridSignFile(
			fileToSign,
			certResult.rsaPrivateKey,
			certResult.mlDsaSecretKey,
			ml_dsa
		);

		console.log('File signed successfully');
		console.log(`RSA signature length: ${signatures.rsaSignature.length} characters`);
		console.log(`${ml_dsa} signature length: ${signatures.pqSignature.length} characters`);

		// Step 3: Verify the signatures
		console.log('\nVerifying signatures...');
		let verificationResult = await x509Hybrid.hybridVerifyFile(
			fileToSign,
			signatures,
			certResult.certificate,
			ml_dsa
		);

		console.log('Verification results:');
		console.log(`  RSA signature valid: ${verificationResult.rsaValid}`);
		console.log(`  ${ml_dsa} signature valid: ${verificationResult.pqValid}`);
		console.log(`  Hybrid verification: ${verificationResult.hybridValid ? 'SUCCESS' : 'FAILED'}`);

		// Step 4: Sign data using both keys		
		const dataToSign = 'Important message that needs post-quantum protection';
		signatures = await x509Hybrid.hybridSignData(
			dataToSign,
			certResult.rsaPrivateKey,
			certResult.mlDsaSecretKey,
			ml_dsa
		);
		console.log('Data signed successfully');
		console.log(`RSA signature length: ${signatures.rsaSignature.length} characters`);
		console.log(`${ml_dsa} signature length: ${signatures.pqSignature.length} characters`);


		// Step 5: Verify the signatures
		console.log('\nVerifying signatures...');
		verificationResult = await x509Hybrid.hybridVerifyData(
			dataToSign,
			signatures,
			certResult.certificate,
			ml_dsa
		);

		console.log('Verification results:');
		console.log(`  RSA signature valid: ${verificationResult.rsaValid}`);
		console.log(`  ${ml_dsa} signature valid: ${verificationResult.pqValid}`);
		console.log(`  Hybrid verification: ${verificationResult.hybridValid ? 'SUCCESS' : 'FAILED'}`);

		return {
			certificate: certResult.certificate,
			verificationResult
		};

		

	} catch (error) {
		console.error('Error in example:', error);
		return { error: error.message };
	}
}


module.exports = { X509Hybrid, example };