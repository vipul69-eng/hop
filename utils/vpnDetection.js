const axios = require('axios');

/**
 * Comprehensive VPN/Proxy detection
 */
class VPNDetector {
  constructor() {
    // Known VPN/proxy/hosting ASNs
    this.suspiciousASNs = new Set([
      'AS16509', // Amazon AWS
      'AS15169', // Google Cloud
      'AS8075',  // Microsoft Azure
      'AS14061', // DigitalOcean
      'AS20473', // Vultr
      'AS24940', // Hetzner
      'AS62240', // Clouvider
      'AS47583', // Hostinger
      // Add more as needed
    ]);
    
    // Known VPN providers
    this.vpnProviders = new Set([
      'nordvpn', 'expressvpn', 'cyberghost', 'surfshark',
      'private internet access', 'protonvpn', 'mullvad',
      'ipvanish', 'tunnelbear', 'windscribe'
    ]);
    
    // Cache for API responses (5 minute TTL)
    this.cache = new Map();
    this.cacheTTL = 5 * 60 * 1000;
  }
  
  /**
   * Main detection method
   */
  async detect(ip, geoData) {
    const cacheKey = `vpn_${ip}`;
    const cached = this.cache.get(cacheKey);
    
    if (cached && Date.now() - cached.timestamp < this.cacheTTL) {
      return cached.result;
    }
    
    const result = {
      ip,
      isVPN: false,
      isProxy: false,
      isHosting: false,
      isTor: false,
      confidence: 0,
      reasons: [],
      riskScore: 0
    };
    
    // Check 1: Hosting provider ASN
    if (geoData.asn) {
      const asnCheck = this.checkASN(geoData.asn, geoData.org);
      if (asnCheck.suspicious) {
        result.isHosting = true;
        result.reasons.push(asnCheck.reason);
        result.riskScore += 30;
      }
    }
    
    // Check 2: Organization name
    if (geoData.org) {
      const orgCheck = this.checkOrganization(geoData.org);
      if (orgCheck.suspicious) {
        result.isVPN = true;
        result.reasons.push(orgCheck.reason);
        result.riskScore += 40;
      }
    }
    
    // Check 3: Use external API for advanced detection
    try {
      const apiCheck = await this.checkWithExternalAPI(ip);
      if (apiCheck) {
        Object.assign(result, apiCheck);
      }
    } catch (error) {
      console.error('External VPN detection failed:', error.message);
    }
    
    // Calculate final confidence
    result.confidence = Math.min(result.riskScore, 100);
    result.isVPN = result.isVPN || result.riskScore >= 50;
    result.isProxy = result.isProxy || result.riskScore >= 40;
    
    // Cache result
    this.cache.set(cacheKey, {
      result,
      timestamp: Date.now()
    });
    
    return result;
  }
  
  /**
   * Check ASN against known hosting/VPN providers
   */
  checkASN(asn, org) {
    const asnStr = asn.toString().includes('AS') ? asn : `AS${asn}`;
    
    if (this.suspiciousASNs.has(asnStr)) {
      return {
        suspicious: true,
        reason: `Hosting provider detected: ${org || asnStr}`
      };
    }
    
    // Check if org name contains hosting keywords
    const hostingKeywords = ['hosting', 'cloud', 'datacenter', 'server', 'vps'];
    if (org) {
      const orgLower = org.toLowerCase();
      for (const keyword of hostingKeywords) {
        if (orgLower.includes(keyword)) {
          return {
            suspicious: true,
            reason: `Hosting/datacenter detected: ${org}`
          };
        }
      }
    }
    
    return { suspicious: false };
  }
  
  /**
   * Check organization name for VPN providers
   */
  checkOrganization(org) {
    const orgLower = org.toLowerCase();
    
    for (const provider of this.vpnProviders) {
      if (orgLower.includes(provider)) {
        return {
          suspicious: true,
          reason: `VPN provider detected: ${org}`
        };
      }
    }
    
    // Check for VPN keywords
    const vpnKeywords = ['vpn', 'proxy', 'privacy', 'anonymous', 'tunnel'];
    for (const keyword of vpnKeywords) {
      if (orgLower.includes(keyword)) {
        return {
          suspicious: true,
          reason: `Suspicious organization name: ${org}`
        };
      }
    }
    
    return { suspicious: false };
  }
  
  /**
   * Use external API for advanced detection
   * Using IPQualityScore (free tier: 5000 requests/month)
   */
  async checkWithExternalAPI(ip) {
    // Skip for private IPs
    if (this.isPrivateIP(ip)) {
      return null;
    }
    
    // You need to sign up at ipqualityscore.com and get an API key
    const apiKey = process.env.IPQS_API_KEY;
    
    if (!apiKey) {
      return null;
    }
    
    try {
      const response = await axios.get(
        `https://ipqualityscore.com/api/json/ip/${apiKey}/${ip}`,
        {
          params: {
            strictness: 1,
            allow_public_access_points: false,
            fast: true
          },
          timeout: 3000
        }
      );
      
      const data = response.data;
      
      return {
        isVPN: data.vpn || false,
        isProxy: data.proxy || false,
        isTor: data.tor || false,
        isHosting: data.host || false,
        riskScore: Math.max(
          data.fraud_score || 0,
          (data.vpn ? 60 : 0),
          (data.proxy ? 50 : 0),
          (data.tor ? 80 : 0)
        ),
        reasons: [
          data.vpn && 'VPN detected by external API',
          data.proxy && 'Proxy detected by external API',
          data.tor && 'Tor exit node detected',
          data.host && 'Hosting provider detected'
        ].filter(Boolean)
      };
    } catch (error) {
      if (error.response?.status === 429) {
        console.warn('VPN detection API rate limit exceeded');
      }
      return null;
    }
  }
  
  isPrivateIP(ip) {
    const ipaddr = require('ipaddr.js');
    try {
      const addr = ipaddr.parse(ip);
      if (addr.kind() === 'ipv4') {
        return addr.match(ipaddr.IPv4.parseCIDR('10.0.0.0/8')) ||
               addr.match(ipaddr.IPv4.parseCIDR('172.16.0.0/12')) ||
               addr.match(ipaddr.IPv4.parseCIDR('192.168.0.0/16')) ||
               addr.match(ipaddr.IPv4.parseCIDR('127.0.0.0/8'));
      }
      return false;
    } catch (error) {
      return false;
    }
  }
}

module.exports = new VPNDetector();