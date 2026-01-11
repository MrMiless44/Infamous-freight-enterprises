module.exports = {
    testEnvironment: 'node',
    testMatch: [
        '**/__tests__/**/*.test.js',
        '**/?(*.)+(spec|test).js'
    ],
    collectCoverageFrom: [
        'src/**/*.js',
        '!src/server.js',
        '!src/swagger.js',
        '!**/node_modules/**',
        '!**/__tests__/**',
        '!**/coverage/**'
    ],
    coverageThreshold: {
        global: {
            branches: 100,
            functions: 100,
            lines: 100,
            statements: 100
        }
    },
    coverageReporters: ['text', 'lcov', 'html', 'json-summary'],
    coverageDirectory: 'coverage',
    verbose: true,
    testTimeout: 10000,
    clearMocks: true,
    resetMocks: true,
    restoreMocks: true,
    setupFilesAfterEnv: ['<rootDir>/jest.setup.js']
};
