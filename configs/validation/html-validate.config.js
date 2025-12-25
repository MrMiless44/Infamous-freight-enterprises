/** @type {import("html-validate").ConfigData} */
module.exports = {
  extends: ["html-validate:recommended"],
  root: true,
  elements: ["html5"],
  rules: {
    "void-style": "error",
    "attribute-boolean-style": ["error", "omit"],
    "no-duplicate-id": "error",
    "aria-label-misuse": "error",
  },
  ignoreFiles: [
    "**/node_modules/**",
    "**/.next/**",
    "**/dist/**",
    "**/coverage/**",
    "**/build/**",
    "**/playwright-report/**",
    "**/test-results/**",
  ],
};
