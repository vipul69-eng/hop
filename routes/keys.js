const express = require('express');
const router = express.Router();
const { authenticate } = require('../middleware/auth');
const { validateKeyCreation } = require('../middleware/validation');
const keyController = require('../controllers/keyController');

router.post('/create', authenticate, validateKeyCreation, keyController.createKey);
router.get('/', authenticate, keyController.listKeys);
router.get('/:keyId', authenticate, keyController.getKey);
router.delete('/:keyId', authenticate, keyController.deleteKey);

// Real API key management
router.post('/:keyId/real-keys', authenticate, keyController.addRealKey);
router.delete('/:keyId/real-keys/:realKeyId', authenticate, keyController.deleteRealKey);

module.exports = router;