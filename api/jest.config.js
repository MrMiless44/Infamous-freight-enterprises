module.exports = {
  testEnvironment: "node",
  collectCoverage: true,
  collectCoverageFrom: [
    "src/**/*.js",
    "!src/**/*.test.js",
    "!src/**/*.spec.js",
    "!**/node_modules/**",
  ],
  coverageThreshold: {
    global: {
      branches: 50,
      functions: 50,
      lines: 50,
      statements: 50,
    },
  },
  coverageReporters: ["text", "lcov", "json", "html"],
  testMatch: ["**/__tests__/**/*.js", "**/?(*.)+(spec|test).js"],
  coveragePathIgnorePatterns: ["/node_modules/"],
  // Handle ES modules in monorepo
  transformIgnorePatterns: ["node_modules/(?!(@infamous-freight)/)"],
  moduleNameMapper: {
    "^@infamous-freight/shared$": "<rootDir>/../packages/shared/src/index.ts",
  },
};
