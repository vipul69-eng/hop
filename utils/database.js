const pool = require('../config/database');

class Database {
  // User operations
  async createUser(userData) {
    const query = `
      INSERT INTO users (email, password_hash, name, organization, role)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING id, email, name, organization, role, status, created_at
    `;
    
    const values = [
      userData.email,
      userData.passwordHash,
      userData.name,
      userData.organization || null,
      userData.role || 'developer'
    ];
    
    const result = await pool.query(query, values);
    return result.rows[0];
  }
  
  async getUserByEmail(email) {
    const query = 'SELECT * FROM users WHERE email = $1';
    const result = await pool.query(query, [email]);
    return result.rows[0];
  }
  
  async getUserById(userId) {
    const query = 'SELECT id, email, name, organization, role, status, created_at FROM users WHERE id = $1';
    const result = await pool.query(query, [userId]);
    return result.rows[0];
  }
  
  // API Key operations
  async saveKey(keyData) {
    const client = await pool.connect();
    
    try {
      await client.query('BEGIN');
      
      // Insert main masked key
      const keyQuery = `
        INSERT INTO api_keys (
          id, user_id, name, masked_key, key_hash,
          environment, default_geo_country, default_geo_cities, 
          default_geo_radius_km, default_geo_mode,
          ip_whitelist, routing_strategy, status
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
        RETURNING *
      `;
      
      const keyValues = [
        keyData.id,
        keyData.userId,
        keyData.name,
        keyData.maskedKey,
        keyData.keyHash,
        keyData.environment,
        keyData.defaultGeoChip?.country,
        keyData.defaultGeoChip?.cities,
        keyData.defaultGeoChip?.radiusKm,
        keyData.defaultGeoChip?.mode,
        keyData.ipWhitelist,
        keyData.routingStrategy || 'region_first',
        keyData.status
      ];
      
      const keyResult = await client.query(keyQuery, keyValues);
      const savedKey = keyResult.rows[0];
      
      // Insert real API keys
      const realKeys = [];
      for (const realKey of keyData.realApiKeys) {
        const realKeyQuery = `
          INSERT INTO real_api_keys (
            api_key_id, encrypted_real_key, provider, provider_key_name,
            custom_base_url, custom_auth_header, custom_auth_prefix,
            geo_regions, geo_countries, geo_cities, geo_priority,
            is_fallback, fallback_priority, status
          )
          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
          RETURNING *
        `;
        
        const realKeyValues = [
          keyData.id,
          JSON.stringify(realKey.encryptedRealKey),
          realKey.provider,
          realKey.providerKeyName,
          realKey.customBaseURL || null,
          realKey.customAuthHeader || 'authorization',
          realKey.customAuthPrefix || 'Bearer',
          realKey.geoRegions || [],
          realKey.geoCountries || [],
          realKey.geoCities || [],
          realKey.geoPriority || 0,
          realKey.isFallback || false,
          realKey.fallbackPriority || 0,
          'active'
        ];
        
        const realKeyResult = await client.query(realKeyQuery, realKeyValues);
        realKeys.push(realKeyResult.rows[0]);
      }
      
      await client.query('COMMIT');
      
      return {
        ...this._formatKeyResult(savedKey),
        realApiKeys: realKeys.map(rk => this._formatRealKeyResult(rk))
      };
      
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }
  
  async getKeysByUser(userId) {
    const query = `
      SELECT 
        ak.*,
        json_agg(
          json_build_object(
            'id', rak.id,
            'provider', rak.provider,
            'providerKeyName', rak.provider_key_name,
            'geoRegions', rak.geo_regions,
            'geoCountries', rak.geo_countries,
            'geoCities', rak.geo_cities,
            'geoPriority', rak.geo_priority,
            'isFallback', rak.is_fallback,
            'fallbackPriority', rak.fallback_priority,
            'status', rak.status,
            'requestCount', rak.request_count,
            'successCount', rak.success_count,
            'failureCount', rak.failure_count_total,
            'lastSuccessAt', rak.last_success_at,
            'lastFailureAt', rak.last_failure_at
          )
          ORDER BY rak.geo_priority DESC, rak.fallback_priority
        ) as real_api_keys
      FROM api_keys ak
      LEFT JOIN real_api_keys rak ON ak.id = rak.api_key_id
      WHERE ak.user_id = $1 
      GROUP BY ak.id
      ORDER BY ak.created_at DESC
    `;
    
    const result = await pool.query(query, [userId]);
    return result.rows.map(row => ({
      ...this._formatKeyResult(row),
      realApiKeys: row.real_api_keys.filter(rk => rk.id !== null)
    }));
  }
  
  async getKeyById(keyId, userId) {
    const query = `
      SELECT 
        ak.*,
        json_agg(
          json_build_object(
            'id', rak.id,
            'provider', rak.provider,
            'providerKeyName', rak.provider_key_name,
            'geoRegions', rak.geo_regions,
            'geoCountries', rak.geo_countries,
            'geoCities', rak.geo_cities,
            'geoPriority', rak.geo_priority,
            'isFallback', rak.is_fallback,
            'fallbackPriority', rak.fallback_priority,
            'status', rak.status,
            'requestCount', rak.request_count,
            'successCount', rak.success_count,
            'failureCount', rak.failure_count_total,
            'lastSuccessAt', rak.last_success_at,
            'lastFailureAt', rak.last_failure_at
          )
          ORDER BY rak.geo_priority DESC, rak.fallback_priority
        ) as real_api_keys
      FROM api_keys ak
      LEFT JOIN real_api_keys rak ON ak.id = rak.api_key_id
      WHERE ak.id = $1 AND ak.user_id = $2
      GROUP BY ak.id
    `;
    
    const result = await pool.query(query, [keyId, userId]);
    if (!result.rows[0]) return null;
    
    return {
      ...this._formatKeyResult(result.rows[0]),
      realApiKeys: result.rows[0].real_api_keys.filter(rk => rk.id !== null)
    };
  }
  
  async getKeyByHash(keyHash) {
    const query = `
      SELECT 
        ak.*,
        json_agg(
          json_build_object(
            'id', rak.id,
            'encryptedRealKey', rak.encrypted_real_key,
            'provider', rak.provider,
            'providerKeyName', rak.provider_key_name,
            'geoRegions', rak.geo_regions,
            'geoCountries', rak.geo_countries,
            'geoCities', rak.geo_cities,
            'geoPriority', rak.geo_priority,
            'isFallback', rak.is_fallback,
            'fallbackPriority', rak.fallback_priority,
            'status', rak.status
          )
          ORDER BY rak.geo_priority DESC, rak.fallback_priority
        ) as real_api_keys
      FROM api_keys ak
      LEFT JOIN real_api_keys rak ON ak.id = rak.api_key_id
      WHERE ak.key_hash = $1 AND ak.status = 'active' AND rak.status = 'active'
      GROUP BY ak.id
    `;
    
    const result = await pool.query(query, [keyHash]);
    if (!result.rows[0]) return null;
    
    return {
      ...this._formatKeyResult(result.rows[0]),
      realApiKeys: result.rows[0].real_api_keys
        .filter(rk => rk.id !== null)
        .map(rk => ({
          ...rk,
          encryptedRealKey: typeof rk.encryptedRealKey === 'string'
            ? JSON.parse(rk.encryptedRealKey)
            : rk.encryptedRealKey
        }))
    };
  }
  
  // Real API Key management
  async addRealApiKey(apiKeyId, realKeyData) {
    const query = `
      INSERT INTO real_api_keys (
        api_key_id, encrypted_real_key, provider, provider_key_name,
        custom_base_url, custom_auth_header, custom_auth_prefix,
        geo_regions, geo_countries, geo_cities, geo_priority,
        is_fallback, fallback_priority, status
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
      RETURNING *
    `;
    
    const values = [
      apiKeyId,
      JSON.stringify(realKeyData.encryptedRealKey),
      realKeyData.provider,
      realKeyData.providerKeyName,
      realKeyData.customBaseURL || null,
      realKeyData.customAuthHeader || 'authorization',
      realKeyData.customAuthPrefix || 'Bearer',
      realKeyData.geoRegions || [],
      realKeyData.geoCountries || [],
      realKeyData.geoCities || [],
      realKeyData.geoPriority || 0,
      realKeyData.isFallback || false,
      realKeyData.fallbackPriority || 0,
      'active'
    ];
    
    const result = await pool.query(query, values);
    return this._formatRealKeyResult(result.rows[0]);
  }
     
  
  async updateRealApiKeyStatus(realKeyId, status, failureInfo = null) {
    let query = `
      UPDATE real_api_keys 
      SET status = $1, updated_at = CURRENT_TIMESTAMP
    `;
    const values = [status, realKeyId];
    
    if (status === 'failed' && failureInfo) {
      query += `, failure_count = failure_count + 1, last_failure_at = CURRENT_TIMESTAMP`;
    } else if (status === 'active') {
      query += `, failure_count = 0, last_success_at = CURRENT_TIMESTAMP, success_count = success_count + 1`;
    }
    
    query += ` WHERE id = $2 RETURNING *`;
    
    const result = await pool.query(query, values);
    return result.rows[0] ? this._formatRealKeyResult(result.rows[0]) : null;
  }
  
  async deleteRealApiKey(realKeyId, apiKeyId) {
    const query = `
      DELETE FROM real_api_keys 
      WHERE id = $1 AND api_key_id = $2
      RETURNING id
    `;
    
    const result = await pool.query(query, [realKeyId, apiKeyId]);
    return result.rowCount > 0;
  }
  
  // Select best real API key based on geo and health
  async selectBestRealKey(apiKeyId, clientGeo) {
    const query = `
      SELECT * FROM real_api_keys
      WHERE api_key_id = $1 
        AND status IN ('active', 'rate_limited')
        AND (
          -- Match by country
          $2 = ANY(geo_countries)
          -- Or global key (empty geo arrays)
          OR (COALESCE(array_length(geo_countries, 1), 0) = 0 
              AND COALESCE(array_length(geo_regions, 1), 0) = 0)
        )
      ORDER BY 
        -- Prioritize exact country match
        CASE WHEN $2 = ANY(geo_countries) THEN 0 ELSE 1 END,
        -- Then by priority
        geo_priority DESC,
        -- Then by health (fewer recent failures)
        failure_count ASC,
        -- Finally by success rate
        CASE WHEN request_count > 0 
          THEN success_count::float / request_count 
          ELSE 0 
        END DESC
      LIMIT 1
    `;
    
    const result = await pool.query(query, [apiKeyId, clientGeo.country]);
    return result.rows[0] ? this._formatRealKeyResult(result.rows[0]) : null;
  }
  
  // Get fallback keys when primary fails
  async getFallbackKeys(apiKeyId) {
    const query = `
      SELECT * FROM real_api_keys
      WHERE api_key_id = $1 
        AND status = 'active'
        AND is_fallback = true
      ORDER BY fallback_priority ASC, failure_count ASC
    `;
    
    const result = await pool.query(query, [apiKeyId]);
    return result.rows.map(row => this._formatRealKeyResult(row));
  }
  async deleteKey(keyId, userId){
    const query = `
      DELETE FROM api_keys 
      WHERE id = $1 AND user_id = $2
      RETURNING id
    `;
    
    const result = await pool.query(query, [keyId, userId]);
    return result.rowCount > 0;
  }
  
  async updateKeyUsage(keyId) {
    const query = `
      UPDATE api_keys 
      SET last_used_at = CURRENT_TIMESTAMP, 
          request_count = request_count + 1
      WHERE id = $1
      RETURNING *
    `;
    
    const result = await pool.query(query, [keyId]);
    return result.rows[0] ? this._formatKeyResult(result.rows[0]) : null;
  }
  
  // Request log operations
  async logRequest(logData) {
    const query = `
      INSERT INTO request_logs (
        api_key_id, method, path, status_code,
        client_ip, geo_country, geo_city, geo_lat, geo_lng,
        geo_allowed, ip_allowed, blocked, block_reason, response_time_ms
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
      RETURNING id
    `;
    
    const values = [
      logData.apiKeyId,
      logData.method,
      logData.path,
      logData.statusCode,
      logData.clientIp,
      logData.geoCountry,
      logData.geoCity,
      logData.geoLat,
      logData.geoLng,
      logData.geoAllowed,
      logData.ipAllowed,
      logData.blocked,
      logData.blockReason,
      logData.responseTimeMs
    ];
    
    const result = await pool.query(query, values);
    return result.rows[0];
  }
  
  // Audit log operations
  async logAudit(auditData) {
    const query = `
      INSERT INTO audit_logs (
        user_id, action, resource_type, resource_id, details, ip_address, user_agent
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      RETURNING id
    `;
    
    const values = [
      auditData.userId,
      auditData.action,
      auditData.resourceType,
      auditData.resourceId,
      JSON.stringify(auditData.details || {}),
      auditData.ipAddress,
      auditData.userAgent
    ];
    
    const result = await pool.query(query, values);
    return result.rows[0];
  }
  
  // Analytics
  async getKeyAnalytics(keyId, userId, days = 7) {
    const query = `
      SELECT 
        DATE_TRUNC('day', timestamp) as date,
        COUNT(*) as total_requests,
        COUNT(*) FILTER (WHERE blocked = true) as blocked_requests,
        AVG(response_time_ms) as avg_response_time,
        COUNT(DISTINCT geo_country) as unique_countries
      FROM request_logs
      WHERE api_key_id = $1 
        AND timestamp >= NOW() - INTERVAL '${days} days'
        AND api_key_id IN (SELECT id FROM api_keys WHERE user_id = $2)
      GROUP BY date
      ORDER BY date DESC
    `;
    
    const result = await pool.query(query, [keyId, userId]);
    return result.rows;
  }
  
  // Helper method to format key results
  _formatKeyResult(row) {
    return {
      id: row.id,
      userId: row.user_id,
      name: row.name,
      maskedKey: row.masked_key,
      keyHash: row.key_hash,
      environment: row.environment,
      defaultGeoChip: {
        country: row.default_geo_country,
        cities: row.default_geo_cities || [],
        radiusKm: row.default_geo_radius_km,
        mode: row.default_geo_mode
      },
      ipWhitelist: row.ip_whitelist || [],
      routingStrategy: row.routing_strategy,
      status: row.status,
      lastUsedAt: row.last_used_at,
      requestCount: parseInt(row.request_count),
      createdAt: row.created_at,
      updatedAt: row.updated_at
    };
  }
  
  _formatRealKeyResult(row) {
    return {
      id: row.id,
      provider: row.provider,
      providerKeyName: row.provider_key_name,
      customBaseURL: row.custom_base_url,
      customAuthHeader: row.custom_auth_header,
      customAuthPrefix: row.custom_auth_prefix,
      encryptedRealKey: typeof row.encrypted_real_key === 'string'
        ? JSON.parse(row.encrypted_real_key)
        : row.encrypted_real_key,
      geoRegions: row.geo_regions || [],
      geoCountries: row.geo_countries || [],
      geoCities: row.geo_cities || [],
      geoPriority: row.geo_priority,
      isFallback: row.is_fallback,
      fallbackPriority: row.fallback_priority,
      status: row.status,
      failureCount: row.failure_count,
      lastFailureAt: row.last_failure_at,
      lastSuccessAt: row.last_success_at,
      requestCount: parseInt(row.request_count || 0),
      successCount: parseInt(row.success_count || 0),
      failureCountTotal: parseInt(row.failure_count_total || 0),
      createdAt: row.created_at,
      updatedAt: row.updated_at
    };
  }
}

module.exports = new Database();