module.exports = {
  extends: ["stylelint-config-standard"],
  ignoreFiles: [
    "**/node_modules/**",
    "**/.next/**",
    "**/dist/**",
    "**/coverage/**",
    "**/build/**",
    "**/public/**",
    "**/test-results/**",
  ],
  rules: {
    "no-descending-specificity": null,
  },
};
