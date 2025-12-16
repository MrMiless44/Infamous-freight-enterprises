/**
 * API Version Detection Middleware
 * 
 * Detects API version from:
 * 1. Header: X-API-Version
 * 2. Query param: ?version=
 * 3. Path prefix: /api/v2/...
 * 4. Accept header: application/vnd.api.v2+json
 * 
 * Sets req.apiVersion (defaults to 'v1')
 */

const { logger } = require('./logger');

// Supported versions
const SUPPORTED_VERSIONS = ['v1', 'v2'];
const DEFAULT_VERSION = 'v1';

/**
 * Extract version from Accept header
 * Example: application/vnd.api.v2+json -> v2
 */
function parseAcceptHeader(acceptHeader) {
  if (!acceptHeader) return null;
  
  const match = acceptHeader.match(/application\/vnd\.api\.(v\d+)\+json/);
  return match ? match[1] : null;
}

/**
 * Extract version from path
 * Example: /api/v2/command -> v2
 */
function parseVersionFromPath(path) {
  const match = path.match(/\/api\/(v\d+)\//);
  return match ? match[1] : null;
}

/**
 * Validate and normalize version
 */
function normalizeVersion(version) {
  if (!version) return null;
  
  // Normalize to lowercase
  const normalized = version.toLowerCase();
  
  // Check if supported
  return SUPPORTED_VERSIONS.includes(normalized) ? normalized : null;
}

/**
 * Version detection middleware
 */
function detectApiVersion(req, res, next) {
  let version = null;

  // Priority 1: X-API-Version header
  if (req.headers['x-api-version']) {
    version = normalizeVersion(req.headers['x-api-version']);
  }

  // Priority 2: Query parameter
  if (!version && req.query.version) {
    version = normalizeVersion(req.query.version);
  }

  // Priority 3: Path prefix
  if (!version) {
    version = parseVersionFromPath(req.path);
  }

  // Priority 4: Accept header
  if (!version) {
    version = parseAcceptHeader(req.headers.accept);
  }

  // Default to v1
  req.apiVersion = version || DEFAULT_VERSION;

  logger.debug('[Version] Detected API version', {
    version: req.apiVersion,
    path: req.path,
    method: req.method
  });

  next();
}

/**
 * Require specific version middleware
 */
function requireVersion(requiredVersion) {
  return (req, res, next) => {
    if (req.apiVersion !== requiredVersion) {
      return res.status(400).json({
        ok: false,
        error: {
          message: `This endpoint requires API version ${requiredVersion}`,
          code: 'VERSION_MISMATCH',
          currentVersion: req.apiVersion,
          requiredVersion
        }
      });
    }
    next();
  };
}

/**
 * Deprecation warning middleware
 */
function deprecationWarning(message, sunsetDate) {
  return (req, res, next) => {
    res.setHeader('X-API-Deprecated', 'true');
    res.setHeader('X-API-Deprecation-Message', message);
    if (sunsetDate) {
      res.setHeader('X-API-Sunset', sunsetDate);
    }

    logger.warn('[Version] Deprecated API called', {
      path: req.path,
      version: req.apiVersion,
      message
    });

    next();
  };
}

module.exports = {
  detectApiVersion,
  requireVersion,
  deprecationWarning,
  SUPPORTED_VERSIONS,
  DEFAULT_VERSION
};
