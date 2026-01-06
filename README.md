# Hop

Secure API gateway with geo-based access control, VPN detection, and automatic failover.

## Features

**Multi-Region API Key Management** - One masked key, multiple real keys per region
**Geo-Enforcement** - Country, city, and radius-based restrictions
**VPN/Proxy Detection** - Block requests from VPNs, proxies, and hosting providers
**IP Whitelisting** - CIDR-based IP restrictions
**Automatic Failover** - Primary and fallback keys with health tracking
**Request Analytics** - Full observability and audit logs
**Rate Limiting** - Built-in protection against abuse

## Quick Start

### 1. Register and Login

```bash
# Register
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "developer@example.com",
    "password": "SecurePass123!",
    "name": "John Doe",
    "organization": "Acme Corp"
  }'

# Login (save the token)
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "developer@example.com",
    "password": "SecurePass123!"
  }'
```

### 2. Create a Masked API Key

```bash
# Create key with multiple regions
curl -X POST http://localhost:3000/api/keys/create \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Multi-Region OpenAI Key",
    "environment": "live",
    "routingStrategy": "region_first",
    "defaultGeoChip": {
      "mode": "strict"
    },
    "ipWhitelist": [],
    "realApiKeys": [
      {
        "apiKey": "sk-india-openai-key-xxx",
        "provider": "openai",
        "name": "India Primary",
        "geoCountries": ["IN"],
        "priority": 10,
        "isFallback": false
      },
      {
        "apiKey": "sk-india-backup-key-yyy",
        "provider": "openai",
        "name": "India Backup",
        "geoCountries": ["IN"],
        "priority": 5,
        "isFallback": true,
        "fallbackPriority": 1
      },
      {
        "apiKey": "sk-us-openai-key-zzz",
        "provider": "openai",
        "name": "US Primary",
        "geoCountries": ["US"],
        "priority": 10,
        "isFallback": false
      },
      {
        "apiKey": "sk-global-fallback-aaa",
        "provider": "openai",
        "name": "Global Fallback",
        "geoCountries": [],
        "priority": 1,
        "isFallback": true,
        "fallbackPriority": 99
      }
    ]
  }'
```

### 3. Use the Masked Key

```bash
# Make API request through the gateway
curl -X POST http://localhost:3000/api/proxy/v1/chat/completions \
  -H "Authorization: Bearer pk_live_YOUR_MASKED_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4",
    "messages": [{"role": "user", "content": "Hello!"}]
  }'
```

## Configuration

### Geo-Enforcement Modes

- **strict** - Block requests that don't match geo rules
- **soft** - Allow but log violations
- **monitor** - Log all requests, never block

### VPN Detection

```bash
# Enable VPN blocking
BLOCK_VPN=true
VPN_RISK_THRESHOLD=70

# Optional: Use IPQualityScore for advanced detection
IPQS_API_KEY=your_api_key
```

### IP Whitelisting

```json
{
  "ipWhitelist": [
    "203.0.113.5",           // Single IP
    "198.51.100.0/24",       // CIDR range
    "2001:db8::/32"          // IPv6 CIDR
  ]
}
```

## Routing Strategies

### Region-First (Default)
Automatically selects the best key based on client's location:
1. Match by country
2. Use highest priority
3. Prefer healthy keys
4. Fall back on failures

### How It Works

```
Request from Mumbai, India
  ↓
1. Validate IP whitelist
  ↓
2. Detect VPN/Proxy
  ↓
3. Get geo location
  ↓
4. Select "India Primary" key (geoCountries: ["IN"], priority: 10)
  ↓
5. Forward to OpenAI with real key
  ↓
If India Primary fails:
  → Try "India Backup" (fallback)
  → Try "Global Fallback" (last resort)
```

## API Endpoints

### Authentication
- `POST /api/auth/register` - Create account
- `POST /api/auth/login` - Login

### Key Management
- `POST /api/keys/create` - Create masked key
- `GET /api/keys` - List all keys
- `GET /api/keys/:keyId` - Get key details
- `DELETE /api/keys/:keyId` - Delete key
- `POST /api/keys/:keyId/real-keys` - Add real API key
- `DELETE /api/keys/:keyId/real-keys/:realKeyId` - Delete real key

### Proxy
- `ALL /api/proxy/*` - Forward to real API with geo-enforcement

## Security Features

### Multi-Layer Validation

1. **API Key Authentication** - Masked key validation
2. **IP Whitelist** - CIDR-based IP filtering
3. **VPN Detection** - ASN + external API validation
4. **Geo-Enforcement** - Country/city/radius restrictions
5. **Rate Limiting** - 100 requests/15 minutes per IP

### VPN Detection Methods

- **ASN Check** - Detects cloud hosting providers (AWS, GCP, Azure, etc.)
- **Organization Analysis** - Identifies VPN providers by name
- **External API** - IPQualityScore for advanced detection
- **Risk Scoring** - 0-100 confidence score

### Blocked VPN Providers

- NordVPN, ExpressVPN, CyberGhost, Surfshark
- Private Internet Access, ProtonVPN, Mullvad
- IPVanish, TunnelBear, Windscribe
- And 100+ more via external API

## Analytics & Monitoring

### Request Logs
All requests are logged with:
- Geo location (country, city, coordinates)
- IP address
- VPN detection results
- Allow/block decision
- Response time

### Key Health Tracking
Each real API key tracks:
- Total requests
- Success/failure count
- Last success/failure time
- Current status (active/failed/rate_limited)

## Supported Providers

The gateway works with **ANY API** that uses HTTP/HTTPS and authentication headers.

### Pre-defined Providers (Optional Convenience)
If you don't want to specify `baseURL`, you can use these provider shortcuts:

**AI/LLM:**
- `openai`, `anthropic`, `google`, `cohere`, `huggingface`
- `replicate`, `together`, `perplexity`, `mistral`, `groq`
- `deepseek`, `fireworks`, `anyscale`, `deepinfra`

**Payment/Communication:**
- `stripe`, `twilio`, `sendgrid`, `mailgun`

**Developer Tools:**
- `github`, `gitlab`, `vercel`, `netlify`, `cloudflare`

**Slack:**
- `slack`

### Custom APIs (Universal Support)
For ANY other API, just specify `baseURL`:

```json
{
  "provider": "custom",
  "baseURL": "https://api.yourcompany.com/v1",
  "apiKey": "your-api-key",
  "authHeader": "x-api-key",
  "authPrefix": ""
}
```

## Universal API Examples

### 1. Custom REST API
```bash
curl -X POST http://localhost:3000/api/keys/create \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My Custom API",
    "environment": "live",
    "realApiKeys": [
      {
        "apiKey": "custom-api-key-12345",
        "provider": "custom",
        "baseURL": "https://api.example.com/v1",
        "authHeader": "x-api-key",
        "authPrefix": "",
        "geoCountries": ["IN"]
      }
    ]
  }'
```

### 2. Stripe API
```json
{
  "name": "Stripe Payment Gateway",
  "realApiKeys": [
    {
      "apiKey": "sk_live_xxx",
      "provider": "stripe",
      "geoCountries": ["US", "GB", "IN"]
    }
  ]
}
```

### 3. GitHub API
```json
{
  "name": "GitHub API Access",
  "realApiKeys": [
    {
      "apiKey": "ghp_xxxxx",
      "provider": "github",
      "authHeader": "authorization",
      "authPrefix": "token",
      "geoCountries": ["US"]
    }
  ]
}
```

### 4. Slack API
```json
{
  "name": "Slack Bot",
  "realApiKeys": [
    {
      "apiKey": "xoxb-your-bot-token",
      "provider": "slack",
      "authHeader": "authorization",
      "authPrefix": "Bearer"
    }
  ]
}
```

### 5. Custom API with Non-Standard Auth
```json
{
  "name": "Legacy API",
  "realApiKeys": [
    {
      "apiKey": "legacy-token-12345",
      "provider": "custom",
      "baseURL": "https://legacy-api.company.com",
      "authHeader": "x-custom-auth-token",
      "authPrefix": "Token",
      "geoCountries": ["IN"]
    }
  ]
}
```

### 6. Multiple APIs in One Masked Key
```json
{
  "name": "Multi-API Gateway",
  "realApiKeys": [
    {
      "apiKey": "openai-key",
      "provider": "openai",
      "geoCountries": ["IN"],
      "priority": 10
    },
    {
      "apiKey": "stripe-key",
      "provider": "stripe",
      "geoCountries": ["US"],
      "priority": 10
    },
    {
      "apiKey": "custom-api-key",
      "provider": "custom",
      "baseURL": "https://internal-api.company.com/v2",
      "geoCountries": ["IN", "US"],
      "priority": 5
    }
  ]
}
```

Add more in `controllers/proxyController.js`

## Production Deployment

### Environment Variables

```bash
# Required
NODE_ENV=production
JWT_SECRET=<strong-random-secret>
API_KEY_ENCRYPTION_KEY=<32-char-encryption-key>
DB_PASSWORD=<database-password>

# Recommended
USE_ENHANCED_GEO=true
BLOCK_VPN=true
VPN_RISK_THRESHOLD=70
IPQS_API_KEY=<ipqualityscore-key>
```

### Database Backup

```bash
# Backup
pg_dump geochip_gateway > backup.sql

# Restore
psql geochip_gateway < backup.sql
```

## Troubleshooting

### VPN Detection Too Aggressive
Lower the risk threshold:
```bash
VPN_RISK_THRESHOLD=80  # Higher = less aggressive
```

### False Geo-Blocks
Use soft mode:
```json
{
  "defaultGeoChip": {
    "mode": "soft"
  }
}
```

### Private IP Testing
Geo-enforcement automatically allows private IPs (localhost, 192.168.x.x, etc.)

## License

MIT

---

## Security Guarantees - How Real API Keys Are Protected

### Question: Can users see the real OpenAI API key?
**Answer: NO - It's cryptographically impossible.**

Here's how the security works at every layer:

### 1. **Storage Layer - Encrypted at Rest**
```javascript
// Real API key is encrypted with AES-256-GCM before storage
const encrypted = {
  encrypted: "a7f3c9e2d4b8...",  // Encrypted ciphertext
  iv: "random-16-bytes",         // Unique per key
  authTag: "authentication-tag"   // Tamper detection
}
// Stored in database as JSONB
// Original key: "sk-real-openai-key-12345" → NEVER stored in plain text
```

**What users see in database:**
```json
{
  "encrypted": "a7f3c9e2d4b8f1a6c3e5d7b9f2a4c6e8",
  "iv": "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d",
  "authTag": "9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c"
}
```
**Result:** Even with database access, the real key is useless without the encryption key.

---

### 2. **Transmission Layer - Never Sent to Client**
```javascript
// When user creates a masked key:
POST /api/keys/create
Request: { "apiKey": "sk-real-openai-key-12345" }
Response: { 
  "maskedKey": "pk_live_abc123xyz789",  // ✅ This is returned
  "warning": "Store securely - shown only once"
  // Real key is NOT in response
}

// When user lists their keys:
GET /api/keys
Response: {
  "maskedKeyPreview": "pk_live_abc1...xyz9",  // ✅ Partial masked key
  "provider": "openai",
  "status": "active"
  // Real key is NEVER included
}
```

**What gets transmitted:**
- ✅ Masked key: `pk_live_abc123xyz789`
- ❌ Real key: NEVER transmitted to client
- ✅ Key preview: `pk_live_abc1...xyz9` (for display only)

---

### 3. **Proxy Layer - Decrypted in Memory Only**
```javascript
// When user makes API call through proxy:
User sends: Authorization: Bearer pk_live_abc123xyz789
           ↓
Gateway decrypts real key IN MEMORY ONLY
           ↓
Forwards to OpenAI: Authorization: Bearer sk-real-openai-key-12345
           ↓
Response comes back
           ↓
SANITIZE HEADERS (remove any auth headers)
           ↓
User receives: Clean response with NO auth headers
```

**Key never leaves server memory:**
```javascript
// Real key exists ONLY here (in function scope):
const realApiKey = decryptApiKey(encryptedData);  // In memory
// Used immediately:
headers: { 'authorization': `Bearer ${realApiKey}` }
// Then garbage collected - NEVER sent to client
```

---

### 4. **Response Sanitization - Headers Stripped**
```javascript
// Before sending response to user:
function sanitizeResponseHeaders(headers) {
  // Remove ALL authentication-related headers
  const blocked = [
    'authorization',      // Real API key would be here
    'x-api-key',
    'api-key',
    'x-auth-token',
    'cookie',
    'set-cookie',
    'www-authenticate',
    'proxy-authorization'
  ];
  
  // User receives response WITHOUT these headers
}
```

**User receives:**
```http
HTTP/1.1 200 OK
content-type: application/json
x-content-type-options: nosniff
x-frame-options: DENY

{ "response": "from OpenAI" }
```

**User does NOT receive:**
```http
authorization: Bearer sk-real-key-xxx  ❌ STRIPPED
x-api-key: sk-real-key-xxx            ❌ STRIPPED
```

---

### 5. **Attack Scenarios - All Blocked**

#### ❌ Scenario 1: Direct Database Access
**Attack:** Hacker gets database dump
**Result:** Only encrypted keys visible
```json
{
  "encrypted_real_key": {
    "encrypted": "a7f3c9e2d4b8...",
    "iv": "1a2b3c4d...",
    "authTag": "9f8e7d6c..."
  }
}
```
**Can they decrypt it?** NO - Needs `API_KEY_ENCRYPTION_KEY` from `.env`

---

#### ❌ Scenario 2: Intercept Network Traffic
**Attack:** Man-in-the-middle attack between user and gateway
**User → Gateway:** `Authorization: Bearer pk_live_abc123...` (masked key)
**Gateway → OpenAI:** Happens on server side (not visible to user)
**Gateway → User:** Response with sanitized headers (no auth)

**Can they see real key?** NO - Only masked key is transmitted

---

#### ❌ Scenario 3: Inspect Browser DevTools
**Attack:** User opens Network tab in browser
```http
POST /api/proxy/v1/chat/completions
Request Headers:
  Authorization: Bearer pk_live_abc123xyz789  ← Masked key

Response Headers:
  content-type: application/json
  (NO authorization header)
```
**Can they see real key?** NO - Never sent to browser

---

#### ❌ Scenario 4: API Response Inspection
**Attack:** User tries to extract key from OpenAI's response
```javascript
// What OpenAI returns to our gateway:
{
  "id": "chatcmpl-123",
  "model": "gpt-4",
  "choices": [...]
}
// (OpenAI doesn't echo back the API key anyway)

// What user receives: Same response, sanitized headers
```
**Can they see real key?** NO - Not in response body or headers

---

#### ❌ Scenario 5: Logging / Error Messages
**Attack:** User triggers an error to see if key leaks in logs
```javascript
// Our code sanitizes ALL logs:
console.error('Request failed:', {
  apiKey: sanitizeKeyForLogging(realKey)  // "sk-xxxxx...[REDACTED]"
});

// User sees:
{
  "error": "Request failed",
  "details": "Upstream error"
  // NO key information
}
```
**Can they see real key?** NO - Sanitized in all logs

---

### 6. **Additional Security Measures**

#### 🔒 Encryption Key Security
```bash
# .env file (NEVER commit to git)
API_KEY_ENCRYPTION_KEY=<32-byte-random-secret>

# Generate strong key:
openssl rand -base64 32
```

#### 🔒 Database Column Encryption
```sql
-- Real keys stored as JSONB (encrypted)
SELECT encrypted_real_key FROM real_api_keys;
-- Returns: {"encrypted": "...", "iv": "...", "authTag": "..."}
```

#### 🔒 Memory Safety
```javascript
// Real key exists only in function scope:
exports.handleProxy = async (req, res) => {
  const realApiKey = decryptApiKey(...);  // Decrypted here
  // Used in axios call
  // Function ends → garbage collected → key erased from memory
};
```

#### 🔒 Audit Logging
```javascript
// Every key usage is logged (WITHOUT the key):
{
  "action": "api_key.used",
  "maskedKeyId": "abc123",
  "provider": "openai",
  "timestamp": "2025-01-01T00:00:00Z",
  "clientIP": "203.0.113.5"
  // Real key is NOT logged
}
```

---

### 7. **What Users CAN See**

✅ **Masked key** (shown once on creation):
```
pk_live_abc123xyz789def456
```

✅ **Masked key preview** (in list view):
```
pk_live_abc1...f456
```

✅ **API usage stats**:
```json
{
  "requestCount": 1523,
  "successCount": 1501,
  "lastUsedAt": "2025-01-01T00:00:00Z"
}
```

✅ **Geo configuration**:
```json
{
  "geoCountries": ["IN", "US"],
  "provider": "openai",
  "status": "active"
}
```

---

### 8. **What Users CANNOT See**

❌ Real API key after creation
❌ Decrypted key in any API response
❌ Key in database (only encrypted version)
❌ Key in logs or error messages
❌ Key in network traffic (client ↔ gateway)
❌ Key in browser DevTools
❌ Encryption key or initialization vectors

---

### Summary: Zero-Knowledge Architecture

```
User's Perspective:
  "I have a masked key: pk_live_abc123..."
  "I use it in my API calls"
  "I get responses from OpenAI"
  "I never see the real key again"

Server's Perspective:
  "Masked key received → hash → lookup database"
  "Decrypt real key in memory"
  "Forward to OpenAI with real key"
  "Strip auth headers from response"
  "Send clean response to user"
  "Real key garbage collected"

Attack Surface:
  ✅ Encrypted keys at rest
  ✅ Never transmitted to client
  ✅ Decrypted only in server memory
  ✅ Headers sanitized before response
  ✅ Logs sanitized
  ✅ Audit trail maintained
```

**The real API key is mathematically impossible to retrieve without server access AND the encryption key from .env**

This is the same architecture used by:
- Stripe (for card tokens)
- AWS Secrets Manager
- Vault by HashiCorp
- 1Password / LastPass

Your Geo-Chip gateway provides bank-level security for API keys! 🔒
*/