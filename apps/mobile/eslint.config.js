const { defineConfig } = require("eslint/config");
const expoConfig = require("eslint-config-expo/flat");

module.exports = defineConfig([
  {
    ignores: [
      ".expo/**",
      "android/**",
      "modules/*/android/**",
      "modules/*/ios/**",
      "src/generated/**",
    ],
  },
  expoConfig,
]);
