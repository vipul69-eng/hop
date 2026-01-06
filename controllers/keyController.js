const { nanoid } = require('nanoid');
const crypto = require('crypto');
const { encryptApiKey, generateKeyHash } = require('../utils/crypto');
const db = require('../utils/database');

const KEY_PREFIX_LIVE = 'pk_live_';
const KEY_PREFIX_TEST = 'pk_test_';

exports.createKey = async (req, res, next) => {
  try {
    const { 
      name, 
      realApiKeys, // Now an array of real keys
      environment = 'test',
      defaultGeoChip = {},
      ipWhitelist = [],
      routingStrategy = 'region_first'
    } = req.body;
    
    const userId = req.user.id;
    
    // Validate realApiKeys array
    if (!realApiKeys || !Array.isArray(realApiKeys) || realApiKeys.length === 0) {
      return res.status(400).json({
        success: false,
        error: 'At least one real API key is required'
      });
    }
    
    // Generate masked key
    const keyId = nanoid(24);
    const prefix = environment === 'live' ? KEY_PREFIX_LIVE : KEY_PREFIX_TEST;
    const maskedKey = `${prefix}${keyId}`;
    
    // Generate hash for quick lookup
    const keyHash = generateKeyHash(maskedKey);
    
    // Encrypt all real API keys
    const encryptedRealKeys = realApiKeys.map(rk => ({
      ...rk,
      encryptedRealKey: encryptApiKey(rk.apiKey)
    }));
    
    // Store in database
    const keyData = {
      id: keyId,
      userId,
      name,
      maskedKey,
      keyHash,
      environment,
      defaultGeoChip: {
        country: defaultGeoChip.country || null,
        cities: defaultGeoChip.cities || [],
        radiusKm: defaultGeoChip.radiusKm || 0,
        mode: defaultGeoChip.mode || 'strict'
      },
      ipWhitelist,
      routingStrategy,
      status: 'active',
      realApiKeys: encryptedRealKeys.map(rk => ({
        encryptedRealKey: rk.encryptedRealKey,
        provider: rk.provider || 'custom',
        providerKeyName: rk.name || null,
        customBaseURL: rk.baseURL || null, // ← Custom API base URL
        customAuthHeader: rk.authHeader || 'authorization',
        customAuthPrefix: rk.authPrefix || 'Bearer',
        geoRegions: rk.geoRegions || [],
        geoCountries: rk.geoCountries || [],
        geoCities: rk.geoCities || [],
        geoPriority: rk.priority || 0,
        isFallback: rk.isFallback || false,
        fallbackPriority: rk.fallbackPriority || 0
      }))
    };
    
    const savedKey = await db.saveKey(keyData);
    
    // Log audit
    await db.logAudit({
      userId,
      action: 'api_key.create',
      resourceType: 'api_key',
      resourceId: keyId,
      details: { 
        name, 
        environment, 
        realKeysCount: realApiKeys.length,
        hasDefaultGeoChip: !!defaultGeoChip.country 
      },
      ipAddress: req.ip,
      userAgent: req.headers['user-agent']
    });
    
    res.status(201).json({
      success: true,
      data: {
        id: savedKey.id,
        maskedKey: savedKey.maskedKey,
        name: savedKey.name,
        environment: savedKey.environment,
        defaultGeoChip: savedKey.defaultGeoChip,
        ipWhitelist: savedKey.ipWhitelist,
        routingStrategy: savedKey.routingStrategy,
        realApiKeys: savedKey.realApiKeys.map(rk => ({
          id: rk.id,
          provider: rk.provider,
          providerKeyName: rk.providerKeyName,
          geoCountries: rk.geoCountries,
          geoCities: rk.geoCities,
          priority: rk.geoPriority,
          isFallback: rk.isFallback,
          status: rk.status
        })),
        status: savedKey.status,
        createdAt: savedKey.createdAt,
        warning: 'Store this masked key securely. It will not be shown again.'
      }
    });
    
  } catch (error) {
    next(error);
  }
};

exports.listKeys = async (req, res, next) => {
  try {
    const userId = req.user.id;
    const keys = await db.getKeysByUser(userId);
    
    const sanitizedKeys = keys.map(key => ({
      id: key.id,
      name: key.name,
      maskedKeyPreview: `${key.maskedKey.substring(0, 12)}...${key.maskedKey.slice(-4)}`,
      environment: key.environment,
      defaultGeoChip: key.defaultGeoChip,
      routingStrategy: key.routingStrategy,
      realApiKeysCount: key.realApiKeys?.length || 0,
      realApiKeys: key.realApiKeys?.map(rk => ({
        id: rk.id,
        provider: rk.provider,
        providerKeyName: rk.providerKeyName,
        geoCountries: rk.geoCountries,
        status: rk.status,
        requestCount: rk.requestCount,
        successCount: rk.successCount,
        failureCount: rk.failureCountTotal
      })),
      status: key.status,
      createdAt: key.createdAt,
      lastUsedAt: key.lastUsedAt,
      requestCount: key.requestCount
    }));
    
    res.json({
      success: true,
      data: sanitizedKeys
    });
    
  } catch (error) {
    next(error);
  }
};

exports.getKey = async (req, res, next) => {
  try {
    const { keyId } = req.params;
    const userId = req.user.id;
    
    const key = await db.getKeyById(keyId, userId);
    
    if (!key) {
      return res.status(404).json({
        success: false,
        error: 'Key not found'
      });
    }
    
    res.json({
      success: true,
      data: {
        id: key.id,
        name: key.name,
        maskedKeyPreview: `${key.maskedKey.substring(0, 12)}...${key.maskedKey.slice(-4)}`,
        environment: key.environment,
        defaultGeoChip: key.defaultGeoChip,
        ipWhitelist: key.ipWhitelist,
        routingStrategy: key.routingStrategy,
        realApiKeys: key.realApiKeys?.map(rk => ({
          id: rk.id,
          provider: rk.provider,
          providerKeyName: rk.providerKeyName,
          geoCountries: rk.geoCountries,
          geoCities: rk.geoCities,
          geoPriority: rk.geoPriority,
          isFallback: rk.isFallback,
          fallbackPriority: rk.fallbackPriority,
          status: rk.status,
          requestCount: rk.requestCount,
          successCount: rk.successCount,
          failureCount: rk.failureCountTotal,
          lastSuccessAt: rk.lastSuccessAt,
          lastFailureAt: rk.lastFailureAt
        })),
        status: key.status,
        createdAt: key.createdAt,
        lastUsedAt: key.lastUsedAt,
        requestCount: key.requestCount
      }
    });
    
  } catch (error) {
    next(error);
  }
};

exports.deleteKey = async (req, res, next) => {
  try {
    const { keyId } = req.params;
    const userId = req.user.id;
    
    const deleted = await db.deleteKey(keyId, userId);
    
    if (!deleted) {
      return res.status(404).json({
        success: false,
        error: 'Key not found'
      });
    }
    
    // Log audit
    await db.logAudit({
      userId,
      action: 'api_key.delete',
      resourceType: 'api_key',
      resourceId: keyId,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent']
    });
    
    res.json({
      success: true,
      message: 'API key deleted successfully'
    });
    
  } catch (error) {
    next(error);
  }
};

// Add a real API key to an existing masked key
exports.addRealKey = async (req, res, next) => {
  try {
    const { keyId } = req.params;
    const userId = req.user.id;
    const {
      apiKey,
      provider,
      name,
      geoCountries = [],
      geoCities = [],
      priority = 0,
      isFallback = false,
      fallbackPriority = 0
    } = req.body;
    
    // Verify user owns this masked key
    const maskedKey = await db.getKeyById(keyId, userId);
    if (!maskedKey) {
      return res.status(404).json({
        success: false,
        error: 'Masked key not found'
      });
    }
    
    // Encrypt the real API key
    const encryptedRealKey = encryptApiKey(apiKey);
    
    // Add to database
    const realKey = await db.addRealApiKey(keyId, {
      encryptedRealKey,
      provider: provider || 'unknown',
      providerKeyName: name,
      geoRegions: [],
      geoCountries,
      geoCities,
      geoPriority: priority,
      isFallback,
      fallbackPriority
    });
    
    // Log audit
    await db.logAudit({
      userId,
      action: 'real_api_key.add',
      resourceType: 'real_api_key',
      resourceId: realKey.id,
      details: { maskedKeyId: keyId, provider, geoCountries },
      ipAddress: req.ip,
      userAgent: req.headers['user-agent']
    });
    
    res.status(201).json({
      success: true,
      data: {
        id: realKey.id,
        provider: realKey.provider,
        providerKeyName: realKey.providerKeyName,
        geoCountries: realKey.geoCountries,
        geoCities: realKey.geoCities,
        priority: realKey.geoPriority,
        isFallback: realKey.isFallback,
        status: realKey.status
      }
    });
    
  } catch (error) {
    next(error);
  }
};

// Delete a specific real API key
exports.deleteRealKey = async (req, res, next) => {
  try {
    const { keyId, realKeyId } = req.params;
    const userId = req.user.id;
    
    // Verify user owns this masked key
    const maskedKey = await db.getKeyById(keyId, userId);
    if (!maskedKey) {
      return res.status(404).json({
        success: false,
        error: 'Masked key not found'
      });
    }
    
    const deleted = await db.deleteRealApiKey(realKeyId, keyId);
    
    if (!deleted) {
      return res.status(404).json({
        success: false,
        error: 'Real API key not found'
      });
    }
    
    // Log audit
    await db.logAudit({
      userId,
      action: 'real_api_key.delete',
      resourceType: 'real_api_key',
      resourceId: realKeyId,
      details: { maskedKeyId: keyId },
      ipAddress: req.ip,
      userAgent: req.headers['user-agent']
    });
    
    res.json({
      success: true,
      message: 'Real API key deleted successfully'
    });
    
  } catch (error) {
    next(error);
  }
};