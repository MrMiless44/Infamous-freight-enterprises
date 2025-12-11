const nextConfig = require("eslint-config-next");

module.exports = [
  ...nextConfig,
  {
    // Explicitly ignore local build artefacts.
    ignores: ["node_modules", "out"],
  },
];
