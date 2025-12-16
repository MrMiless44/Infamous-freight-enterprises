/**
 * Shared test fixtures and factory functions
 */

/**
 * Create a valid shipment object
 * @param {object} overrides - Override default properties
 * @returns {object} Shipment object
 */
function createShipment(overrides = {}) {
    return {
        id: overrides.id || 'test-shipment-1',
        trackingNumber: overrides.trackingNumber || `TEST-${Date.now()}`,
        origin: overrides.origin || 'New York, NY',
        destination: overrides.destination || 'Los Angeles, CA',
        status: overrides.status || 'PENDING',
        weight: overrides.weight || 25.5,
        priority: overrides.priority || 'standard',
        createdAt: overrides.createdAt || new Date(),
        updatedAt: overrides.updatedAt || new Date(),
        userId: overrides.userId || 'test-user-1',
        driverId: overrides.driverId || null,
        ...overrides
    }
}

/**
 * Create multiple shipments
 * @param {number} count - Number of shipments to create
 * @param {object} baseOverrides - Common overrides for all shipments
 * @returns {array} Array of shipment objects
 */
function createShipments(count = 3, baseOverrides = {}) {
    return Array.from({ length: count }, (_, i) =>
        createShipment({
            ...baseOverrides,
            id: `test-shipment-${i + 1}`,
            trackingNumber: `TEST-${Date.now()}-${i + 1}`
        })
    )
}

/**
 * Create a valid user object
 * @param {object} overrides - Override default properties
 * @returns {object} User object
 */
function createUser(overrides = {}) {
    return {
        id: overrides.id || 'test-user-1',
        email: overrides.email || `test${Date.now()}@example.com`,
        name: overrides.name || 'Test User',
        role: overrides.role || 'user',
        phone: overrides.phone || '+1234567890',
        createdAt: overrides.createdAt || new Date(),
        updatedAt: overrides.updatedAt || new Date(),
        ...overrides
    }
}

/**
 * Create a driver object
 * @param {object} overrides - Override default properties
 * @returns {object} Driver object
 */
function createDriver(overrides = {}) {
    return {
        id: overrides.id || 'test-driver-1',
        userId: overrides.userId || 'test-user-1',
        licenseNumber: overrides.licenseNumber || 'DL123456',
        vehicleInfo: overrides.vehicleInfo || 'Truck XYZ',
        status: overrides.status || 'AVAILABLE',
        currentLocation: overrides.currentLocation || null,
        createdAt: overrides.createdAt || new Date(),
        updatedAt: overrides.updatedAt || new Date(),
        ...overrides
    }
}

/**
 * Malicious input patterns for security testing
 */
const maliciousInputs = [
    // XSS attacks
    '<script>alert("xss")</script>',
    '<img src=x onerror=alert("xss")>',
    'javascript:alert("xss")',
    "<iframe src='javascript:alert(1)'>",

    // SQL injection
    "'; DROP TABLE users; --",
    "1' OR '1'='1",
    "admin'--",
    "1' UNION SELECT NULL--",

    // Path traversal
    '../../../etc/passwd',
    '..\\..\\..\\windows\\system32',
    '/etc/shadow',

    // Command injection
    '; ls -la',
    '| cat /etc/passwd',
    '$(whoami)',
    '`id`',

    // Buffer overflow
    'A'.repeat(10000),
    'A'.repeat(100000),

    // Format string
    '%s%s%s%s%s',
    '%x%x%x%x',

    // Null bytes
    'test\x00.txt',
    'user\x00admin',

    // Unicode/special characters
    'test\u0000user',
    'admin\uFEFF'
]

/**
 * Edge case inputs for validation testing
 */
const edgeCaseInputs = [
    // Empty/null/undefined
    '',
    null,
    undefined,

    // Whitespace
    ' ',
    '   ',
    '\t',
    '\n',

    // Very long strings
    'a'.repeat(255),
    'a'.repeat(256),
    'a'.repeat(1000),

    // Special characters
    '@#$%^&*()',
    '测试用户', // Chinese
    'тест', // Cyrillic
    'مستخدم', // Arabic

    // Numbers as strings
    '0',
    '-1',
    '999999999999',
    '1.234567890123456',

    // Boolean-like strings
    'true',
    'false',
    'null',
    'undefined'
]

/**
 * AI command test payloads
 */
const aiTestCommands = {
    valid: {
        command: 'shipment.optimize',
        payload: {
            shipments: ['TEST-001', 'TEST-002'],
            constraints: { maxHours: 24 }
        }
    },
    invalid: {
        command: '', // Empty command
        payload: null
    },
    large: {
        command: 'route.calculate',
        payload: {
            waypoints: Array.from({ length: 1000 }, (_, i) => ({
                lat: 40 + i * 0.01,
                lng: -74 + i * 0.01
            }))
        }
    }
}

module.exports = {
    createShipment,
    createShipments,
    createUser,
    createDriver,
    maliciousInputs,
    edgeCaseInputs,
    aiTestCommands
}
