const axios = require('axios');
const { decryptApiKey } = require('../utils/crypto');
const db = require('../utils/database');

/**
 * Main proxy handler - forwards requests to ANY API
 */
exports.handleProxy = async (req, res) => {
  const startTime = req.startTime || Date.now();
  
  try {
    const { apiKey, selectedRealKey, geoData, clientIP } = req;
    
    // Decrypt the real API key
    const realApiKey = decryptApiKey(selectedRealKey.encryptedRealKey);
    
    // Determine target URL
    let targetURL;
    
    if (selectedRealKey.customBaseURL) {
      // Custom API - use the provided base URL
      targetURL = getCustomTargetURL(selectedRealKey.customBaseURL, req.path);
    } else {
      // Pre-defined provider (backward compatibility)
      targetURL = getTargetURL(selectedRealKey.provider, req.path);
    }
    
    if (!targetURL) {
      return res.status(400).json({
        success: false,
        error: 'Invalid provider configuration - baseURL is required'
      });
    }
    
    // Prepare headers for forwarding
    const authHeader = selectedRealKey.customAuthHeader || 'authorization';
    const authPrefix = selectedRealKey.customAuthPrefix || 'Bearer';

    const forwardHeaders = {
      ...req.headers,
      'x-forwarded-for': clientIP,
      'x-geo-country': geoData.country,
      'x-geo-city': geoData.city
    };

    // Remove host header and any original auth to avoid conflicts,
    // then set the forwarded auth header with the decrypted real key.
    delete forwardHeaders.host;
    delete forwardHeaders.authorization;

    // Remove content length/transfer-encoding so Axios can compute correct values
    // (forwarding client's content-length can cause upstream connection resets)
    delete forwardHeaders['content-length'];
    delete forwardHeaders['transfer-encoding'];

    // Set the auth header intended for upstream after removing originals
    forwardHeaders[authHeader.toLowerCase()] = `${authPrefix} ${realApiKey}`;
    
    // Forward the request
    const response = await axios({
      method: req.method,
      url: targetURL,
      headers: forwardHeaders,
      data: req.body,
      params: req.query,
      timeout: 60000, // 60 second timeout
      validateStatus: () => true, // Don't throw on any status code
      maxRedirects: 5
    });
    
    const responseTimeMs = Date.now() - startTime;
    
    // Update key usage
    await db.updateKeyUsage(apiKey.id);
    
    // Mark real key as successful
    if (response.status >= 200 && response.status < 300) {
      await db.updateRealApiKeyStatus(selectedRealKey.id, 'active');
    } else if (response.status === 429) {
      // Rate limited
      await db.updateRealApiKeyStatus(selectedRealKey.id, 'rate_limited');
    } else if (response.status >= 500) {
      // Server error - mark as failed
      await db.updateRealApiKeyStatus(selectedRealKey.id, 'failed', {
        statusCode: response.status,
        error: response.data
      });
    }
    
    // Log successful request
    await db.logRequest({
      apiKeyId: apiKey.id,
      method: req.method,
      path: req.path,
      statusCode: response.status,
      clientIp: clientIP,
      geoCountry: geoData.country,
      geoCity: geoData.city,
      geoLat: geoData.lat,
      geoLng: geoData.lng,
      geoAllowed: true,
      ipAllowed: true,
      blocked: false,
      blockReason: null,
      responseTimeMs
    });
    
    // Sanitize response body (prevent key leakage in echoed responses)
    const sanitizedBody = sanitizeResponseBody(response.data, realApiKey);
    
    // Forward response with sanitized headers and body
    res.status(response.status)
       .set(sanitizeResponseHeaders(response.headers))
       .send(sanitizedBody);
    
  } catch (error) {
    console.error('Proxy error:', error);
    
    const responseTimeMs = Date.now() - startTime;
    
    // Try failover to next key
    if (req.selectedRealKey && !req.selectedRealKey.isFallback) {
      const fallbackKeys = await db.getFallbackKeys(req.apiKey.id);
      
      if (fallbackKeys.length > 0) {
        // Mark current key as failed
        await db.updateRealApiKeyStatus(req.selectedRealKey.id, 'failed');
        
        // Retry with fallback key
        req.selectedRealKey = fallbackKeys[0];
        return exports.handleProxy(req, res);
      }
    }
    
    // Log failed request
    await db.logRequest({
      apiKeyId: req.apiKey.id,
      method: req.method,
      path: req.path,
      statusCode: 502,
      clientIp: req.clientIP,
      geoCountry: req.geoData.country,
      geoCity: req.geoData.city,
      geoLat: req.geoData.lat,
      geoLng: req.geoData.lng,
      geoAllowed: true,
      ipAllowed: true,
      blocked: false,
      blockReason: `Proxy error: ${error.message}`,
      responseTimeMs
    });
    
    res.status(502).json({
      success: false,
      error: 'Failed to forward request to upstream API',
      details: error.message
    });
  }
};

/**
 * Sanitize response headers to prevent key leakage
 */
function sanitizeResponseHeaders(headers) {
  const sanitized = { ...headers };
  
  // Remove headers that might expose real API keys or internal info
  const headersToRemove = [
    'authorization',
    'x-api-key',
    'api-key',
    'x-real-ip',
    'x-forwarded-for',
    'x-forwarded-host',
    'x-forwarded-proto',
    'x-auth-token',
    'x-access-token',
    'cookie',
    'set-cookie',
    'proxy-authorization',
    'www-authenticate',
    'proxy-authenticate'
  ];
  
  headersToRemove.forEach(header => {
    delete sanitized[header];
    delete sanitized[header.toLowerCase()];
  });
  
  // Add security headers
  sanitized['x-content-type-options'] = 'nosniff';
  sanitized['x-frame-options'] = 'DENY';
  sanitized['strict-transport-security'] = 'max-age=31536000; includeSubDomains';
  
  // Remove server identification
  delete sanitized['server'];
  delete sanitized['x-powered-by'];
  
  return sanitized;
}

/**
 * Sanitize response body to prevent key leakage
 * Some APIs might echo back parts of the request
 */
function sanitizeResponseBody(body, realApiKey) {
  if (!body) return body;
  
  // If body is string, check for key patterns
  if (typeof body === 'string') {
    // Remove exact key match
    body = body.replace(new RegExp(realApiKey, 'g'), '[REDACTED]');
    
    // Remove patterns that look like API keys
    body = body.replace(/sk-[a-zA-Z0-9]{40,}/g, 'sk-[REDACTED]');
    body = body.replace(/Bearer\s+sk-[a-zA-Z0-9]{40,}/g, 'Bearer sk-[REDACTED]');
    
    return body;
  }
  
  // If body is object, recursively sanitize
  if (typeof body === 'object' && body !== null) {
    const sanitized = Array.isArray(body) ? [] : {};
    
    for (const key in body) {
      if (body.hasOwnProperty(key)) {
        // Skip fields that might contain sensitive auth data
        if (['authorization', 'api_key', 'apiKey', 'token', 'secret'].includes(key.toLowerCase())) {
          sanitized[key] = '[REDACTED]';
        } else {
          sanitized[key] = sanitizeResponseBody(body[key], realApiKey);
        }
      }
    }
    
    return sanitized;
  }
  
  return body;
}

/**
 * Get target URL based on provider (pre-defined providers for convenience)
 * This is OPTIONAL - users can specify custom baseURL instead
 */
function getTargetURL(provider, path) {
  // Common API providers (for convenience - not required)
  const providers = {
    'openai': 'https://api.openai.com',
    'anthropic': 'https://api.anthropic.com',
    'google': 'https://generativelanguage.googleapis.com',
    'cohere': 'https://api.cohere.ai',
    'huggingface': 'https://api-inference.huggingface.co',
    'replicate': 'https://api.replicate.com',
    'together': 'https://api.together.xyz',
    'perplexity': 'https://api.perplexity.ai',
    'mistral': 'https://api.mistral.ai',
    'groq': 'https://api.groq.com',
    'deepseek': 'https://api.deepseek.com',
    'fireworks': 'https://api.fireworks.ai',
    'anyscale': 'https://api.endpoints.anyscale.com',
    'deepinfra': 'https://api.deepinfra.com',
    'stripe': 'https://api.stripe.com',
    'github': 'https://api.github.com',
    'gitlab': 'https://gitlab.com/api',
    'slack': 'https://slack.com/api',
    'twilio': 'https://api.twilio.com',
    'sendgrid': 'https://api.sendgrid.com',
    'mailgun': 'https://api.mailgun.net',
    'aws': 'https://amazonaws.com',
    'vercel': 'https://api.vercel.com',
    'netlify': 'https://api.netlify.com',
    'cloudflare': 'https://api.cloudflare.com/client/v4'
  };
  
  const baseURL = providers[provider.toLowerCase()];
  
  if (!baseURL) {
    return null;
  }
  
  // Remove leading /api/proxy from path
  const cleanPath = path.replace(/^\/+/, '');
  
  return `${baseURL}/${cleanPath}`;
}

/**
 * Get custom target URL (for ANY custom API)
 * This is the UNIVERSAL method - works with any API
 */
function getCustomTargetURL(customBaseURL, path) {
  if (!customBaseURL) {
    return null;
  }
  
  // Remove trailing slash from base URL
  const baseURL = customBaseURL.replace(/\/$/, '');
  
  // Remove leading /api/proxy from path
  const cleanPath = path.replace(/^\/api\/proxy\/?/, '');
  
  // If path is empty, just return base URL
  if (!cleanPath) {
    return baseURL;
  }
  
  // Combine base URL with path
  return `${baseURL}/${cleanPath}`;
}