const express = require('express');
const router = express.Router();
const proxyController = require('../controllers/proxyController');
const { geoEnforce } = require('../middleware/geoEnforce');

// Main proxy endpoint - validates geo rules and forwards to real API
router.all('/*splat', geoEnforce, proxyController.handleProxy);

module.exports = router;