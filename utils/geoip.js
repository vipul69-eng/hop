// utils/geoip.js
const geoip = require('geoip-lite');
const axios = require('axios');

/**
 * Get geo location from IP address
 * Uses geoip-lite for fast local lookup
 */
exports.getGeoFromIP = (ip) => {
  // Handle localhost/private IPs
  if (isPrivateIP(ip)) {
    return {
      ip,
      country: 'XX',
      city: 'Unknown',
      region: 'Unknown',
      lat: 0,
      lng: 0,
      timezone: 'UTC',
      isPrivate: true
    };
  }
  
  const geo = geoip.lookup(ip);
  
  if (!geo) {
    return {
      ip,
      country: 'XX',
      city: 'Unknown',
      region: 'Unknown',
      lat: 0,
      lng: 0,
      timezone: 'UTC',
      notFound: true
    };
  }
  
  return {
    ip,
    country: geo.country,
    city: geo.city || 'Unknown',
    region: geo.region || 'Unknown',
    lat: geo.ll[0],
    lng: geo.ll[1],
    timezone: geo.timezone,
    range: geo.range
  };
};

/**
 * Enhanced geo lookup using external API (for higher accuracy)
 * Use this sparingly due to rate limits and cost
 */
exports.getGeoFromIPEnhanced = async (ip) => {
  if (isPrivateIP(ip)) {
    return exports.getGeoFromIP(ip);
  }
  
  try {
    // Using ipapi.co for enhanced lookup (100 requests/day free)
    const response = await axios.get(`https://ipapi.co/${ip}/json/`, {
      timeout: 3000
    });
    
    const data = response.data;
    
    return {
      ip,
      country: data.country_code || 'XX',
      city: data.city || 'Unknown',
      region: data.region || 'Unknown',
      lat: data.latitude || 0,
      lng: data.longitude || 0,
      timezone: data.timezone || 'UTC',
      asn: data.asn || null,
      org: data.org || null,
      enhanced: true
    };
  } catch (error) {
    // Fallback to local lookup
    return exports.getGeoFromIP(ip);
  }
};

/**
 * Calculate distance between two coordinates in kilometers
 */
exports.calculateDistance = (lat1, lng1, lat2, lng2) => {
  const R = 6371; // Earth's radius in km
  const dLat = toRad(lat2 - lat1);
  const dLng = toRad(lng2 - lng1);
  
  const a = Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) *
    Math.sin(dLng / 2) * Math.sin(dLng / 2);
  
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  const distance = R * c;
  
  return distance;
};

function toRad(degrees) {
  return degrees * (Math.PI / 180);
}

function isPrivateIP(ip) {
  const ipaddr = require('ipaddr.js');
  
  try {
    const addr = ipaddr.parse(ip);
    
    if (addr.kind() === 'ipv4') {
      return addr.match(ipaddr.IPv4.parseCIDR('10.0.0.0/8')) ||
             addr.match(ipaddr.IPv4.parseCIDR('172.16.0.0/12')) ||
             addr.match(ipaddr.IPv4.parseCIDR('192.168.0.0/16')) ||
             addr.match(ipaddr.IPv4.parseCIDR('127.0.0.0/8'));
    }
    
    if (addr.kind() === 'ipv6') {
      return addr.range() === 'loopback' || 
             addr.range() === 'linkLocal' ||
             addr.range() === 'uniqueLocal';
    }
    
    return false;
  } catch (error) {
    return false;
  }
}