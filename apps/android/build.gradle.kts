// The Tunnet Android app: a VpnService that hosts the Tunnet agent in-process
// (crates/tunnet-mobile, packaged as libtunnet_mobile.so) and drives it through
// the same Local Management API the CLI and desktop app use.
plugins {
    id("com.android.application") version "8.13.2" apply false
    kotlin("android") version "2.0.21" apply false
    kotlin("plugin.compose") version "2.0.21" apply false
}
