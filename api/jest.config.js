module.exports = {
  testEnvironment: "node",
  collectCoverageFrom: ["src/**/*.js", "!src/**/*.test.js"],
  testMatch: ["**/__tests__/**/*.js", "**/?(*.)+(spec|test).js"],
  coveragePathIgnorePatterns: ["/node_modules/"],
};
