const {
  withAppBuildGradle,
  withProjectBuildGradle,
} = require("expo/config-plugins");

// expo-build-properties cannot express a pinned NDK, build-type-specific ABI
// filters, or the existing environment-based release signing contract.
const ndkVersion = "30.0.16248370";

function replaceRequired(source, marker, replacement) {
  const first = source.indexOf(marker);
  if (first < 0) {
    throw new Error(
      `Tunnet Android config plugin could not find generated Gradle marker:\n${marker}`,
    );
  }
  if (source.indexOf(marker, first + marker.length) >= 0) {
    throw new Error(
      `Tunnet Android config plugin found an ambiguous Gradle marker:\n${marker}`,
    );
  }
  return (
    source.slice(0, first) + replacement + source.slice(first + marker.length)
  );
}

module.exports = function withTunnetAndroid(config) {
  config = withProjectBuildGradle(config, (projectConfig) => {
    projectConfig.modResults.contents = replaceRequired(
      projectConfig.modResults.contents,
      "buildscript {\n",
      `buildscript {\n  ext.ndkVersion = "${ndkVersion}"\n`,
    );
    return projectConfig;
  });

  config = withAppBuildGradle(config, (appConfig) => {
    let contents = appConfig.modResults.contents;

    contents = replaceRequired(
      contents,
      `        debug {
            storeFile file('debug.keystore')
            storePassword 'android'
            keyAlias 'androiddebugkey'
            keyPassword 'android'
        }
`,
      `        debug {
            storeFile file('debug.keystore')
            storePassword 'android'
            keyAlias 'androiddebugkey'
            keyPassword 'android'
        }
        if (System.getenv('ANDROID_KEYSTORE_PATH')) {
            release {
                storeFile file(System.getenv('ANDROID_KEYSTORE_PATH'))
                storePassword System.getenv('ANDROID_KEYSTORE_PASSWORD')
                keyAlias System.getenv('ANDROID_KEY_ALIAS')
                keyPassword System.getenv('ANDROID_KEY_PASSWORD')
            }
        }
`,
    );

    contents = replaceRequired(
      contents,
      `        debug {
            signingConfig signingConfigs.debug
        }
        release {
            // Caution! In production, you need to generate your own keystore file.
            // see https://reactnative.dev/docs/signed-apk-android.
            signingConfig signingConfigs.debug
`,
      `        debug {
            ndk { abiFilters 'arm64-v8a', 'x86_64' }
            signingConfig signingConfigs.debug
        }
        release {
            ndk { abiFilters 'arm64-v8a' }
            if (System.getenv('ANDROID_KEYSTORE_PATH')) {
                signingConfig signingConfigs.release
            }
`,
    );

    contents = replaceRequired(
      contents,
      "// Apply static values from `gradle.properties` to the `android.packagingOptions`",
      `// React Native's global architecture property otherwise widens every build type.
androidComponents {
    finalizeDsl { extension ->
        extension.defaultConfig.ndk.abiFilters.clear()
    }
}

// Apply static values from \`gradle.properties\` to the \`android.packagingOptions\``,
    );

    appConfig.modResults.contents = contents;
    return appConfig;
  });

  return config;
};
