import { readFileSync } from "node:fs";
import path from "node:path";

import type { ConfigContext, ExpoConfig } from "expo/config";

import { cargoWorkspaceVersion, resolveAppVersion } from "./config/version.js";

const workspaceRoot = path.resolve(__dirname, "../..");

function androidVersion() {
  const cargoVersion = cargoWorkspaceVersion(
    readFileSync(path.join(workspaceRoot, "Cargo.toml"), "utf8"),
  );

  return resolveAppVersion({
    injected: process.env.TUNNET_VERSION,
    cargoVersion,
  });
}

export default ({ config }: ConfigContext): ExpoConfig => {
  const version = androidVersion();
  const publicVersion = version.version;

  return {
    ...config,
    name: "Tunnet",
    slug: "tunnet",
    version: publicVersion,
    platforms: ["android", "ios"],
    orientation: "portrait",
    icon: "./assets/images/icon.png",
    scheme: "tunnet",
    userInterfaceStyle: "automatic",
    android: {
      ...config.android,
      package: "io.tunnet.android",
      version: version.version,
      versionCode: version.versionCode,
      allowBackup: false,
      blockedPermissions: [
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
      ],
      adaptiveIcon: {
        backgroundColor: "#12141A",
        foregroundImage: "./assets/images/android-icon-foreground.png",
        backgroundImage: "./assets/images/android-icon-background.png",
        monochromeImage: "./assets/images/android-icon-monochrome.png",
      },
      predictiveBackGestureEnabled: false,
    },
    plugins: [
      "expo-router",
      [
        "expo-splash-screen",
        {
          backgroundColor: "#12141A",
          image: "./assets/images/splash-icon.png",
          imageWidth: 76,
        },
      ],
      [
        "expo-build-properties",
        {
          android: {
            compileSdkVersion: 37,
            targetSdkVersion: 37,
            minSdkVersion: 26,
            buildArchs: ["arm64-v8a", "x86_64"],
            useDayNightTheme: true,
            cmakeVersion: "4.1.2",
          },
        },
      ],
      "./plugins/with-tunnet-android",
    ],
    experiments: {
      autolinkingModuleResolution: true,
      typedRoutes: true,
      reactCompiler: true,
    },
  };
};
