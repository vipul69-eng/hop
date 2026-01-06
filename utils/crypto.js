const crypto = require('crypto');

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16;
const AUTH_TAG_LENGTH = 16;
const SALT_LENGTH = 32;

// Derive a proper encryption key from the environment variable
function getEncryptionKey() {
  const keySource = process.env.API_KEY_ENCRYPTION_KEY;
  
  if (!keySource || keySource === 'default-key-please-change-this-32b') {
    console.warn('WARNING: Using default encryption key. Set API_KEY_ENCRYPTION_KEY in production!');
  }
  
  // Use PBKDF2 to derive a proper 256-bit key
  const salt = Buffer.from('geochip-api-gateway-salt-v1'); // Static salt for deterministic key derivation
  return crypto.pbkdf2Sync(
    keySource || 'default-key-please-change-this-32b',
    salt,
    100000,
    32,
    'sha256'
  );
}

const ENCRYPTION_KEY = getEncryptionKey();

/**
 * Encrypt an API key using AES-256-GCM
 * @param {string} apiKey - The plain text API key to encrypt
 * @returns {Object} - Object containing encrypted data, IV, and auth tag
 */
exports.encryptApiKey = (apiKey) => {
  if (!apiKey || typeof apiKey !== 'string') {
    throw new Error('API key must be a non-empty string');
  }
  
  try {
    // Generate a random initialization vector
    const iv = crypto.randomBytes(IV_LENGTH);
    
    // Create cipher
    const cipher = crypto.createCipheriv(ALGORITHM, ENCRYPTION_KEY, iv);
    
    // Encrypt the API key
    let encrypted = cipher.update(apiKey, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    // Get the authentication tag
    const authTag = cipher.getAuthTag();
    
    return {
      encrypted,
      iv: iv.toString('hex'),
      authTag: authTag.toString('hex'),
      algorithm: ALGORITHM
    };
  } catch (error) {
    console.error('Encryption error:', error);
    throw new Error('Failed to encrypt API key');
  }
};

/**
 * Decrypt an API key using AES-256-GCM
 * @param {Object} encryptedData - Object containing encrypted data, IV, and auth tag
 * @returns {string} - The decrypted API key
 */
exports.decryptApiKey = (encryptedData) => {
  if (!encryptedData || !encryptedData.encrypted || !encryptedData.iv || !encryptedData.authTag) {
    throw new Error('Invalid encrypted data format');
  }
  
  try {
    // Create decipher
    const decipher = crypto.createDecipheriv(
      ALGORITHM,
      ENCRYPTION_KEY,
      Buffer.from(encryptedData.iv, 'hex')
    );
    
    // Set the authentication tag
    decipher.setAuthTag(Buffer.from(encryptedData.authTag, 'hex'));
    
    // Decrypt the data
    let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  } catch (error) {
    console.error('Decryption error:', error);
    throw new Error('Failed to decrypt API key - data may be corrupted or tampered with');
  }
};

/**
 * Generate a SHA-256 hash of the masked key for quick database lookup
 * @param {string} maskedKey - The masked API key (e.g., pk_live_xxx)
 * @returns {string} - Hex-encoded hash
 */
exports.generateKeyHash = (maskedKey) => {
  if (!maskedKey || typeof maskedKey !== 'string') {
    throw new Error('Masked key must be a non-empty string');
  }
  
  return crypto
    .createHash('sha256')
    .update(maskedKey)
    .digest('hex');
};

/**
 * Verify that a masked key matches its hash
 * @param {string} maskedKey - The masked API key to verify
 * @param {string} storedHash - The stored hash to compare against
 * @returns {boolean} - True if the key matches the hash
 */
exports.verifyKeyHash = (maskedKey, storedHash) => {
  try {
    const computedHash = exports.generateKeyHash(maskedKey);
    return crypto.timingSafeEqual(
      Buffer.from(computedHash, 'hex'),
      Buffer.from(storedHash, 'hex')
    );
  } catch (error) {
    return false;
  }
};

/**
 * Generate a cryptographically secure random token
 * @param {number} length - Length in bytes (default: 32)
 * @returns {string} - Hex-encoded random token
 */
exports.generateSecureToken = (length = 32) => {
  return crypto.randomBytes(length).toString('hex');
};

/**
 * Generate HMAC signature for request validation
 * @param {string} payload - The payload to sign
 * @param {string} secret - The secret key
 * @returns {string} - Hex-encoded HMAC signature
 */
exports.generateHMAC = (payload, secret) => {
  return crypto
    .createHmac('sha256', secret)
    .update(payload)
    .digest('hex');
};

/**
 * Verify HMAC signature
 * @param {string} payload - The payload to verify
 * @param {string} signature - The signature to verify against
 * @param {string} secret - The secret key
 * @returns {boolean} - True if signature is valid
 */
exports.verifyHMAC = (payload, signature, secret) => {
  try {
    const expectedSignature = exports.generateHMAC(payload, secret);
    return crypto.timingSafeEqual(
      Buffer.from(signature, 'hex'),
      Buffer.from(expectedSignature, 'hex')
    );
  } catch (error) {
    return false;
  }
};

/**
 * Hash a password using bcrypt-compatible format
 * Note: This is a simple implementation. Use bcrypt library for production.
 * @param {string} password - The password to hash
 * @returns {string} - Hashed password
 */
exports.hashPassword = async (password) => {
  const bcrypt = require('bcrypt');
  return await bcrypt.hash(password, 12);
};

/**
 * Verify a password against its hash
 * @param {string} password - The password to verify
 * @param {string} hash - The stored hash
 * @returns {boolean} - True if password matches
 */
exports.verifyPassword = async (password, hash) => {
  const bcrypt = require('bcrypt');
  return await bcrypt.compare(password, hash);
};

/**
 * Generate a masked key preview (for display purposes)
 * @param {string} maskedKey - The full masked key
 * @returns {string} - Shortened preview (e.g., "pk_live_abcd...xyz9")
 */
exports.generateKeyPreview = (maskedKey) => {
  if (!maskedKey || maskedKey.length < 16) {
    return maskedKey;
  }
  
  const start = maskedKey.substring(0, 12);
  const end = maskedKey.slice(-4);
  return `${start}...${end}`;
};

/**
 * Generate a request signature for replay attack prevention
 * @param {Object} options - Signature options
 * @param {string} options.method - HTTP method
 * @param {string} options.path - Request path
 * @param {string} options.body - Request body (JSON string)
 * @param {string} options.timestamp - ISO timestamp
 * @param {string} options.nonce - Unique nonce
 * @param {string} options.apiKey - The masked API key
 * @returns {string} - Request signature
 */
exports.generateRequestSignature = ({ method, path, body, timestamp, nonce, apiKey }) => {
  const payload = `${method}|${path}|${body}|${timestamp}|${nonce}`;
  return exports.generateHMAC(payload, apiKey);
};

/**
 * Verify request signature and check for replay attacks
 * @param {Object} options - Verification options
 * @param {string} options.signature - The provided signature
 * @param {string} options.method - HTTP method
 * @param {string} options.path - Request path
 * @param {string} options.body - Request body (JSON string)
 * @param {string} options.timestamp - ISO timestamp
 * @param {string} options.nonce - Unique nonce
 * @param {string} options.apiKey - The masked API key
 * @param {number} options.maxAgeSeconds - Maximum age of request in seconds (default: 300)
 * @returns {Object} - Verification result { valid: boolean, reason?: string }
 */
exports.verifyRequestSignature = ({ 
  signature, 
  method, 
  path, 
  body, 
  timestamp, 
  nonce, 
  apiKey,
  maxAgeSeconds = 300 
}) => {
  // Check timestamp freshness
  try {
    const requestTime = new Date(timestamp).getTime();
    const now = Date.now();
    const age = (now - requestTime) / 1000;
    
    if (age > maxAgeSeconds) {
      return { valid: false, reason: 'Request timestamp too old' };
    }
    
    if (age < -60) {
      return { valid: false, reason: 'Request timestamp is in the future' };
    }
  } catch (error) {
    return { valid: false, reason: 'Invalid timestamp format' };
  }
  
  // Verify signature
  const expectedSignature = exports.generateRequestSignature({
    method,
    path,
    body,
    timestamp,
    nonce,
    apiKey
  });
  
  const isValid = exports.verifyHMAC(
    `${method}|${path}|${body}|${timestamp}|${nonce}`,
    signature,
    apiKey
  );
  
  if (!isValid) {
    return { valid: false, reason: 'Invalid signature' };
  }
  
  return { valid: true };
};

/**
 * Sanitize API key for logging (never log full keys)
 * @param {string} apiKey - The API key to sanitize
 * @returns {string} - Sanitized key for logging
 */
exports.sanitizeKeyForLogging = (apiKey) => {
  if (!apiKey || apiKey.length < 8) {
    return '[REDACTED]';
  }
  
  return `${apiKey.substring(0, 8)}...[REDACTED]`;
};

module.exports = exports;

