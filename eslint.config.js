import js from "@eslint/js";
import prettier from "eslint-config-prettier";

export default [
  {
    ignores: [
      "node_modules/**",
      "dist/**",
      ".next/**",
      "build/**",
      "coverage/**",
      "archive/**",
      "**/*.config.js",
      "**/*.config.ts",
      "mobile/**",
      "**/*.test.js",
      "**/*.spec.js",
    ],
  },
  {
    files: ["**/*.{js,jsx,mjs,cjs,ts,tsx}"],
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "module",
      globals: {
        console: "readonly",
        process: "readonly",
        Buffer: "readonly",
      },
    },
    rules: {
      ...js.configs.recommended.rules,
      "no-console": ["warn", { allow: ["warn", "error"] }],
      "no-unused-vars": ["error", { argsIgnorePattern: "^_" }],
    },
  },
  prettier,
];
