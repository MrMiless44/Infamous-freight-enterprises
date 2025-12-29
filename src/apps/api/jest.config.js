/** @type {import('jest').Config} */
module.exports = {
  // Use Node.js test environment
  testEnvironment: "node",

  // Transform TypeScript files
  preset: "ts-jest",

  // Root directory for tests
  roots: ["<rootDir>/src"],

  // Test match patterns
  testMatch: [
    "**/__tests__/**/*.+(ts|tsx|js)",
    "**/?(*.)+(spec|test).+(ts|tsx|js)",
  ],

  // Transform files
  transform: {
    "^.+\\.(ts|tsx)$": [
      "ts-jest",
      {
        tsconfig: {
          esModuleInterop: true,
          allowSyntheticDefaultImports: true,
        },
      },
    ],
  },

  // Coverage configuration
  collectCoverageFrom: [
    "src/**/*.{ts,tsx}",
    "!src/**/*.d.ts",
    "!src/**/*.test.{ts,tsx}",
    "!src/**/*.spec.{ts,tsx}",
    "!src/**/index.ts",
  ],

  // Coverage thresholds
  coverageThresholds: {
    global: {
      branches: 75,
      functions: 75,
      lines: 80,
      statements: 80,
    },
  },

  // Coverage directory
  coverageDirectory: "./coverage",

  // Coverage reporters
  coverageReporters: ["text", "lcov", "html", "json-summary"],

  // Reporters
  reporters: [
    "default",
    [
      "jest-junit",
      {
        outputDirectory: "./",
        outputName: "junit.xml",
        classNameTemplate: "{classname}",
        titleTemplate: "{title}",
        ancestorSeparator: " › ",
        usePathForSuiteName: true,
      },
    ],
  ],

  // Module path aliases (if needed)
  moduleNameMapper: {
    "^@/(.*)$": "<rootDir>/src/$1",
  },

  // Setup files
  setupFilesAfterEnv: [],

  // Ignore patterns
  testPathIgnorePatterns: ["/node_modules/", "/dist/", "/coverage/"],

  // Clear mocks between tests
  clearMocks: true,

  // Verbose output
  verbose: true,

  // Timeout for tests
  testTimeout: 10000,
};
