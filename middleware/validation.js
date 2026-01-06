exports.validateRegistration = (req, res, next) => {
  const { email, password, name } = req.body;
  
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({
      success: false,
      error: 'Valid email is required'
    });
  }
  
  if (!password || password.length < 8) {
    return res.status(400).json({
      success: false,
      error: 'Password must be at least 8 characters'
    });
  }
  
  if (!name || name.trim().length === 0) {
    return res.status(400).json({
      success: false,
      error: 'Name is required'
    });
  }
  
  next();
};

exports.validateLogin = (req, res, next) => {
  const { email, password } = req.body;
  
  if (!email || !password) {
    return res.status(400).json({
      success: false,
      error: 'Email and password are required'
    });
  }
  
  next();
};

exports.validateKeyCreation = (req, res, next) => {
  const { name, realApiKeys, environment, defaultGeoChip } = req.body;
  
  if (!name || typeof name !== 'string' || name.trim().length === 0) {
    return res.status(400).json({
      success: false,
      error: 'Valid key name is required'
    });
  }
  
  if (!realApiKeys || !Array.isArray(realApiKeys) || realApiKeys.length === 0) {
    return res.status(400).json({
      success: false,
      error: 'At least one real API key is required'
    });
  }
  
  // Validate each real API key
  for (let i = 0; i < realApiKeys.length; i++) {
    const rk = realApiKeys[i];
    
    if (!rk.apiKey || typeof rk.apiKey !== 'string') {
      return res.status(400).json({
        success: false,
        error: `Real API key at index ${i} is invalid`
      });
    }
    
    // Validate baseURL for custom APIs
    if (!rk.provider || rk.provider === 'custom') {
      if (!rk.baseURL) {
        return res.status(400).json({
          success: false,
          error: `baseURL is required for custom API at index ${i}`
        });
      }
      
      // Validate URL format
      try {
        new URL(rk.baseURL);
      } catch (error) {
        return res.status(400).json({
          success: false,
          error: `Invalid baseURL format at index ${i}: ${rk.baseURL}`
        });
      }
    }
    
    // Validate auth configuration
    if (rk.authHeader && typeof rk.authHeader !== 'string') {
      return res.status(400).json({
        success: false,
        error: `authHeader at index ${i} must be a string`
      });
    }
    
    if (rk.authPrefix && typeof rk.authPrefix !== 'string') {
      return res.status(400).json({
        success: false,
        error: `authPrefix at index ${i} must be a string`
      });
    }
    
    if (rk.geoCountries && !Array.isArray(rk.geoCountries)) {
      return res.status(400).json({
        success: false,
        error: `geoCountries at index ${i} must be an array`
      });
    }
    
    // Validate country codes
    if (rk.geoCountries) {
      for (const country of rk.geoCountries) {
        if (!/^[A-Z]{2}$/.test(country)) {
          return res.status(400).json({
            success: false,
            error: `Invalid country code "${country}" at index ${i}. Must be ISO-2 format (e.g., IN, US)`
          });
        }
      }
    }
  }
  
  if (environment && !['test', 'live'].includes(environment)) {
    return res.status(400).json({
      success: false,
      error: 'Environment must be either "test" or "live"'
    });
  }
  
  if (defaultGeoChip) {
    if (defaultGeoChip.country && !/^[A-Z]{2}$/.test(defaultGeoChip.country)) {
      return res.status(400).json({
        success: false,
        error: 'Country must be ISO-2 format (e.g., IN, US)'
      });
    }
    
    if (defaultGeoChip.mode && !['strict', 'soft', 'monitor'].includes(defaultGeoChip.mode)) {
      return res.status(400).json({
        success: false,
        error: 'Mode must be "strict", "soft", or "monitor"'
      });
    }
  }
  
  next();
};
