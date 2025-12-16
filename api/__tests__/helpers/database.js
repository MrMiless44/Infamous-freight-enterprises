/**
 * Database test helpers
 */

/**
 * Clean all test data from database
 * @param {PrismaClient} prisma - Prisma client instance
 */
async function cleanDatabase(prisma) {
    // Delete in order to respect foreign key constraints
    await prisma.aiEvent.deleteMany()
    await prisma.shipment.deleteMany()
    await prisma.driver.deleteMany()
    await prisma.user.deleteMany()
}

/**
 * Seed test data into database
 * @param {PrismaClient} prisma - Prisma client instance
 * @param {object} data - Test data to seed
 */
async function seedDatabase(prisma, data = {}) {
    const users = data.users || []
    const drivers = data.drivers || []
    const shipments = data.shipments || []

    // Create users
    for (const user of users) {
        await prisma.user.create({ data: user })
    }

    // Create drivers
    for (const driver of drivers) {
        await prisma.driver.create({ data: driver })
    }

    // Create shipments
    for (const shipment of shipments) {
        await prisma.shipment.create({ data: shipment })
    }
}

/**
 * Create a test database transaction that rolls back
 * @param {PrismaClient} prisma - Prisma client instance
 * @param {function} testFn - Test function to run in transaction
 */
async function withRollback(prisma, testFn) {
    try {
        await prisma.$transaction(async (tx) => {
            await testFn(tx)
            throw new Error('ROLLBACK_TEST') // Force rollback
        })
    } catch (err) {
        if (err.message !== 'ROLLBACK_TEST') {
            throw err
        }
    }
}

/**
 * Wait for database to be ready
 * @param {PrismaClient} prisma - Prisma client instance
 * @param {number} maxRetries - Maximum retry attempts
 */
async function waitForDatabase(prisma, maxRetries = 10) {
    for (let i = 0; i < maxRetries; i++) {
        try {
            await prisma.$queryRaw`SELECT 1`
            return
        } catch (err) {
            if (i === maxRetries - 1) throw err
            await new Promise((resolve) => setTimeout(resolve, 1000))
        }
    }
}

/**
 * Check if record exists in database
 * @param {PrismaClient} prisma - Prisma client instance
 * @param {string} model - Model name (e.g., 'user', 'shipment')
 * @param {object} where - Query conditions
 * @returns {boolean} True if record exists
 */
async function recordExists(prisma, model, where) {
    const count = await prisma[model].count({ where })
    return count > 0
}

/**
 * Get database record count
 * @param {PrismaClient} prisma - Prisma client instance
 * @param {string} model - Model name
 * @returns {number} Record count
 */
async function getRecordCount(prisma, model) {
    return await prisma[model].count()
}

module.exports = {
    cleanDatabase,
    seedDatabase,
    withRollback,
    waitForDatabase,
    recordExists,
    getRecordCount
}
