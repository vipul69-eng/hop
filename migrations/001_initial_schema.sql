-- Users table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    name VARCHAR(255),
    organization VARCHAR(255),
    role VARCHAR(50) DEFAULT 'developer',
    status VARCHAR(50) DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- API Keys table (main masked key)
CREATE TABLE IF NOT EXISTS api_keys (
    id VARCHAR(50) PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    masked_key VARCHAR(255) UNIQUE NOT NULL,
    key_hash VARCHAR(64) UNIQUE NOT NULL,
    environment VARCHAR(20) NOT NULL CHECK (environment IN ('test', 'live')),
    
    -- Global Geo-Chip configuration (fallback if no region-specific config)
    default_geo_country VARCHAR(2),
    default_geo_cities TEXT[],
    default_geo_radius_km INTEGER DEFAULT 0,
    default_geo_mode VARCHAR(20) DEFAULT 'strict' CHECK (default_geo_mode IN ('strict', 'soft', 'monitor')),
    
    -- IP Whitelist
    ip_whitelist TEXT[],
    
    -- Routing strategy
    routing_strategy VARCHAR(20) DEFAULT 'region_first' CHECK (routing_strategy IN ('region_first', 'round_robin', 'failover_only')),
    
    -- Status and metadata
    status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'revoked')),
    last_used_at TIMESTAMP,
    request_count BIGINT DEFAULT 0,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Real API Keys table (multiple real keys per masked key)
CREATE TABLE IF NOT EXISTS real_api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_key_id VARCHAR(50) NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
    
    -- The actual encrypted API key
    encrypted_real_key JSONB NOT NULL,
    
    -- Provider information
    provider VARCHAR(100) NOT NULL, -- e.g., 'openai', 'anthropic', 'custom'
    provider_key_name VARCHAR(255), -- Optional label like 'OpenAI Production Key 1'
    custom_base_url TEXT, -- For custom APIs: 'https://api.example.com/v1'
    custom_auth_header VARCHAR(100) DEFAULT 'authorization', -- Header name for auth
    custom_auth_prefix VARCHAR(50) DEFAULT 'Bearer', -- Auth prefix: 'Bearer', 'Token', 'ApiKey', etc.
    
    -- Region configuration for this specific key
    geo_regions TEXT[], -- e.g., ['IN', 'US', 'EU'] - empty array means global
    geo_countries VARCHAR(2)[], -- Specific countries e.g., ['IN', 'US']
    geo_cities TEXT[], -- Specific cities
    geo_priority INTEGER DEFAULT 0, -- Higher priority = used first (0 is lowest)
    
    -- Failover configuration
    is_fallback BOOLEAN DEFAULT false, -- Use as fallback if primary keys fail
    fallback_priority INTEGER DEFAULT 0, -- Order of fallback (0 = first fallback)
    
    -- Health and rate limiting
    status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'failed', 'rate_limited')),
    failure_count INTEGER DEFAULT 0,
    last_failure_at TIMESTAMP,
    last_success_at TIMESTAMP,
    rate_limit_reset_at TIMESTAMP,
    
    -- Usage stats
    request_count BIGINT DEFAULT 0,
    success_count BIGINT DEFAULT 0,
    failure_count_total BIGINT DEFAULT 0,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Request Logs table (for analytics)
CREATE TABLE IF NOT EXISTS request_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_key_id VARCHAR(50) REFERENCES api_keys(id) ON DELETE CASCADE,
    
    -- Request details
    method VARCHAR(10),
    path TEXT,
    status_code INTEGER,
    
    -- Geo information
    client_ip INET,
    geo_country VARCHAR(2),
    geo_city VARCHAR(100),
    geo_lat DECIMAL(10, 8),
    geo_lng DECIMAL(11, 8),
    
    -- Enforcement result
    geo_allowed BOOLEAN,
    ip_allowed BOOLEAN,
    blocked BOOLEAN DEFAULT false,
    block_reason TEXT,
    
    -- Timing
    response_time_ms INTEGER,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Audit Logs table (for security and compliance)
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id VARCHAR(100),
    details JSONB,
    ip_address INET,
    user_agent TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for performance
CREATE INDEX idx_api_keys_user_id ON api_keys(user_id);
CREATE INDEX idx_api_keys_key_hash ON api_keys(key_hash);
CREATE INDEX idx_api_keys_status ON api_keys(status);
CREATE INDEX idx_real_api_keys_api_key_id ON real_api_keys(api_key_id);
CREATE INDEX idx_real_api_keys_status ON real_api_keys(status);
CREATE INDEX idx_real_api_keys_geo_countries ON real_api_keys USING GIN(geo_countries);
CREATE INDEX idx_real_api_keys_priority ON real_api_keys(geo_priority DESC, fallback_priority);
CREATE INDEX idx_request_logs_api_key_id ON request_logs(api_key_id);
CREATE INDEX idx_request_logs_timestamp ON request_logs(timestamp DESC);
CREATE INDEX idx_request_logs_blocked ON request_logs(blocked);
CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_timestamp ON audit_logs(timestamp DESC);

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Triggers for updated_at
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_api_keys_updated_at BEFORE UPDATE ON api_keys
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_real_api_keys_updated_at BEFORE UPDATE ON real_api_keys
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();