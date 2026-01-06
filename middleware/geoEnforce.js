const { generateKeyHash } = require('../utils/crypto');
const { getGeoFromIP, getGeoFromIPEnhanced, calculateDistance } = require('../utils/geoip');
const { isIPWhitelisted } = require('../utils/ipWhitelist');
const vpnDetector = require('../utils/vpnDetection');
const db = require('../utils/database');

/**
 * Main geo-enforcement middleware
 */
exports.geoEnforce = async (req, res, next) => {
  const startTime = Date.now();
  
  try {
    // Extract masked API key from Authorization header
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return sendBlockedResponse(req, res, {
        reason: 'Missing or invalid authorization header',
        statusCode: 401,
        blocked: true
      });
    }
    
    const maskedKey = authHeader.substring(7);
    
    // Get client IP (handle proxies)
    const clientIP = getClientIP(req);
    
    if (!clientIP) {
      return sendBlockedResponse(req, res, {
        reason: 'Unable to determine client IP address',
        statusCode: 400,
        blocked: true
      });
    }
    
    // Generate key hash for lookup
    const keyHash = generateKeyHash(maskedKey);
    
    // Get API key configuration from database
    const apiKey = await db.getKeyByHash(keyHash);
    
    if (!apiKey) {
      return sendBlockedResponse(req, res, {
        reason: 'Invalid API key',
        statusCode: 401,
        blocked: true,
        clientIP
      });
    }
    
    if (apiKey.status !== 'active') {
      return sendBlockedResponse(req, res, {
        reason: `API key is ${apiKey.status}`,
        statusCode: 403,
        blocked: true,
        clientIP,
        apiKeyId: apiKey.id
      });
    }
    
    // Step 1: IP Whitelist Check
    const ipAllowed = isIPWhitelisted(clientIP, apiKey.ipWhitelist);
    
    if (!ipAllowed) {
      await logRequest(req, {
        apiKeyId: apiKey.id,
        clientIP,
        ipAllowed: false,
        geoAllowed: false,
        blocked: true,
        blockReason: 'IP not in whitelist',
        statusCode: 403,
        responseTimeMs: Date.now() - startTime
      });
      
      return sendBlockedResponse(req, res, {
        reason: 'IP address not in whitelist',
        statusCode: 403,
        blocked: true,
        clientIP,
        apiKeyId: apiKey.id
      });
    }
    
    // Step 2: Get geo location
    const useEnhancedGeo = process.env.USE_ENHANCED_GEO === 'true';
    const geoData = useEnhancedGeo 
      ? await getGeoFromIPEnhanced(clientIP)
      : getGeoFromIP(clientIP);
    
    // Step 3: VPN/Proxy Detection
    const vpnCheck = await vpnDetector.detect(clientIP, geoData);
    
    // Block VPNs if configured (default: allow, but log)
    const blockVPN = process.env.BLOCK_VPN === 'true';
    const vpnRiskThreshold = parseInt(process.env.VPN_RISK_THRESHOLD || '70');
    
    if (blockVPN && vpnCheck.riskScore >= vpnRiskThreshold) {
      await logRequest(req, {
        apiKeyId: apiKey.id,
        clientIP,
        geoCountry: geoData.country,
        geoCity: geoData.city,
        geoLat: geoData.lat,
        geoLng: geoData.lng,
        ipAllowed: true,
        geoAllowed: false,
        blocked: true,
        blockReason: `VPN/Proxy detected: ${vpnCheck.reasons.join(', ')}`,
        statusCode: 403,
        responseTimeMs: Date.now() - startTime,
        vpnDetected: true,
        vpnRiskScore: vpnCheck.riskScore
      });
      
      return sendBlockedResponse(req, res, {
        reason: 'VPN or proxy detected',
        details: vpnCheck.reasons,
        statusCode: 403,
        blocked: true,
        clientIP,
        apiKeyId: apiKey.id
      });
    }
    
    // Step 4: Geo validation - Select appropriate real API key
    const selectedRealKey = await db.selectBestRealKey(apiKey.id, geoData);
    
    if (!selectedRealKey) {
      // Try fallback keys
      const fallbackKeys = await db.getFallbackKeys(apiKey.id);
      
      if (fallbackKeys.length > 0) {
        req.selectedRealKey = fallbackKeys[0];
      } else {
        await logRequest(req, {
          apiKeyId: apiKey.id,
          clientIP,
          geoCountry: geoData.country,
          geoCity: geoData.city,
          geoLat: geoData.lat,
          geoLng: geoData.lng,
          ipAllowed: true,
          geoAllowed: false,
          blocked: true,
          blockReason: `No API key available for region: ${geoData.country}`,
          statusCode: 403,
          responseTimeMs: Date.now() - startTime
        });
        
        return sendBlockedResponse(req, res, {
          reason: 'No API key configured for your region',
          region: geoData.country,
          statusCode: 403,
          blocked: true,
          clientIP,
          apiKeyId: apiKey.id
        });
      }
    } else {
      req.selectedRealKey = selectedRealKey;
    }
    
    // Step 5: Additional geo rules validation (city, radius)
    const geoValidation = validateGeoRules(
      geoData,
      apiKey.defaultGeoChip,
      req.selectedRealKey
    );
    
    if (!geoValidation.allowed && apiKey.defaultGeoChip.mode === 'strict') {
      await logRequest(req, {
        apiKeyId: apiKey.id,
        clientIP,
        geoCountry: geoData.country,
        geoCity: geoData.city,
        geoLat: geoData.lat,
        geoLng: geoData.lng,
        ipAllowed: true,
        geoAllowed: false,
        blocked: true,
        blockReason: geoValidation.reason,
        statusCode: 403,
        responseTimeMs: Date.now() - startTime
      });
      
      return sendBlockedResponse(req, res, {
        reason: geoValidation.reason,
        statusCode: 403,
        blocked: true,
        clientIP,
        apiKeyId: apiKey.id
      });
    }
    
    // Pass data to proxy controller
    req.apiKey = apiKey;
    req.geoData = geoData;
    req.vpnCheck = vpnCheck;
    req.clientIP = clientIP;
    req.startTime = startTime;
    req.ipAllowed = ipAllowed;
    req.geoAllowed = geoValidation.allowed;
    
    next();
    
  } catch (error) {
    console.error('Geo enforcement error:', error);
    
    return res.status(500).json({
      success: false,
      error: 'Internal server error during geo validation'
    });
  }
};

/**
 * Validate geo rules (city, radius, etc.)
 */
function validateGeoRules(geoData, defaultGeoChip, realKey) {
  // Check country-level restriction
  if (realKey.geoCountries && realKey.geoCountries.length > 0) {
    if (!realKey.geoCountries.includes(geoData.country)) {
      return {
        allowed: false,
        reason: `Country ${geoData.country} not allowed for this key`
      };
    }
  }
  
  // Check city-level restriction
  if (realKey.geoCities && realKey.geoCities.length > 0) {
    const cityMatch = realKey.geoCities.some(city => 
      city.toLowerCase() === geoData.city.toLowerCase()
    );
    
    if (!cityMatch && defaultGeoChip.mode === 'strict') {
      return {
        allowed: false,
        reason: `City ${geoData.city} not in allowed list`
      };
    }
  }
  
  // Check radius restriction (if cities are specified)
  if (defaultGeoChip.radiusKm && defaultGeoChip.radiusKm > 0 && 
      defaultGeoChip.cities && defaultGeoChip.cities.length > 0) {
    
    // This would require city coordinates in the database
    // For now, we'll skip detailed radius checking
    // In production, you'd geocode city names to coordinates
  }
  
  return { allowed: true };
}

/**
 * Get real client IP (handle proxies, load balancers)
 */
function getClientIP(req) {
  return req.headers['x-forwarded-for']?.split(',')[0].trim() ||
         req.headers['x-real-ip'] ||
         req.connection.remoteAddress ||
         req.socket.remoteAddress ||
         req.ip;
}

/**
 * Send blocked response
 */
function sendBlockedResponse(req, res, { reason, details, statusCode, blocked, clientIP, apiKeyId }) {
  res.status(statusCode).json({
    success: false,
    error: reason,
    details: details || undefined,
    blocked: true,
    timestamp: new Date().toISOString()
  });
}

/**
 * Log request to database
 */
async function logRequest(req, logData) {
  try {
    await db.logRequest({
      apiKeyId: logData.apiKeyId,
      method: req.method,
      path: req.path,
      statusCode: logData.statusCode,
      clientIp: logData.clientIP,
      geoCountry: logData.geoCountry,
      geoCity: logData.geoCity,
      geoLat: logData.geoLat,
      geoLng: logData.geoLng,
      geoAllowed: logData.geoAllowed,
      ipAllowed: logData.ipAllowed,
      blocked: logData.blocked,
      blockReason: logData.blockReason,
      responseTimeMs: logData.responseTimeMs
    });
  } catch (error) {
    console.error('Failed to log request:', error);
  }
}