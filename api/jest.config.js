module.exports = {
  testEnvironment: "node",
  setupFilesAfterEnv: ["<rootDir>/jest.setup.js"],
  collectCoverage: true,
  collectCoverageFrom: [
    "src/**/*.js",
    "!src/**/*.test.js",
    "!src/**/*.spec.js",
    "!**/node_modules/**",
  ],
  coverageThreshold: {
    global: {
      branches: 75,
      functions: 80,
      lines: 84,
      statements: 84,
    },
  },
  coverageReporters: ["text", "lcov", "json", "html"],
  reporters: [
    "default",
    [
      "jest-junit",
      {
        outputDirectory: "./test-results",
        outputName: "junit.xml",
      },
    ],
  ],
  testMatch: ["**/__tests__/**/*.js", "**/?(*.)+(spec|test).js"],
  coveragePathIgnorePatterns: ["/node_modules/"],
  // Handle ES modules in monorepo
  transformIgnorePatterns: ["node_modules/(?!(@infamous-freight)/)"],
  moduleNameMapper: {
    "^@infamous-freight/shared$": "<rootDir>/../packages/shared/src/index.ts",
  },
};
