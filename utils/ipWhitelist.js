const ipCidr = require('ip-cidr');
const ipaddr = require('ipaddr.js');

/**
 * IP Whitelist validator
 */
exports.isIPWhitelisted = (clientIP, whitelist) => {
  if (!whitelist || whitelist.length === 0) {
    return true; // No whitelist = allow all
  }
  
  try {
    const addr = ipaddr.parse(clientIP);
    
    for (const entry of whitelist) {
      // Check if entry is CIDR notation
      if (entry.includes('/')) {
        const cidr = new ipCidr(entry);
        if (cidr.contains(clientIP)) {
          return true;
        }
      } else {
        // Direct IP match
        if (clientIP === entry) {
          return true;
        }
      }
    }
    
    return false;
  } catch (error) {
    console.error('IP whitelist validation error:', error);
    return false;
  }
};

/**
 * Validate IP format
 */
exports.isValidIP = (ip) => {
  try {
    ipaddr.parse(ip);
    return true;
  } catch (error) {
    return false;
  }
};