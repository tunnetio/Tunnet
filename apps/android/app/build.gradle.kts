plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
    id("com.google.protobuf")
}

val workspaceRoot: File = rootProject.projectDir.parentFile.parentFile

val NDK_VERSION = "30.0.16248370"
val NDK_PLATFORM = 26
val AGENT_CRATE = "tunnet-mobile"
val CARGO_NDK_VERSION = "4.1.2"

val debugAbis = listOf("arm64-v8a", "x86_64")
val releaseAbis = listOf("arm64-v8a")

val devPlaceholderVersionCode = 1
val devPlaceholderVersionName = "0.0.0"

val cargoVersionLine = Regex("^version\\s*=\\s*\"([^\"]+)\"")

fun parseCargoWorkspaceVersion(cargoToml: String): String? {
    val lines = cargoToml.lineSequence().toList()
    val start = lines.indexOfFirst { it.trim() == "[workspace.package]" }
    if (start < 0) {
        return null
    }
    return lines.drop(start + 1)
        .takeWhile { !it.trim().startsWith("[") }
        .firstNotNullOfOrNull { cargoVersionLine.find(it.trim()) }
        ?.groupValues?.get(1)
}

fun stripTagPrefix(version: String): String =
    if (version.length > 1 && version[0] == 'v' && version[1].isDigit()) version.substring(1) else version

fun versionCodeOf(version: String): Int? {
    val triple = Regex("""^(\d+)\.(\d+)\.(\d+)$""").matchEntire(version) ?: return null
    val (major, minor, patch) = triple.destructured.toList().map(String::toInt)
    if (minor > 99 || patch > 99) {
        throw GradleException(
            "version $version cannot be folded into a monotonic versionCode: minor and patch " +
                "must each be <= 99 for `major * 10000 + minor * 100 + patch` not to collide " +
                "with the next minor/major. Widen the mapping, and never lower a released code.",
        )
    }
    return major * 10000 + minor * 100 + patch
}

val injectedReleaseVersion = providers.environmentVariable("TUNNET_VERSION")
    .map { it.trim() }
    .filter { it.isNotEmpty() }

val gitDescribeVersion = providers.of(GitDescribe::class) {
    parameters.repoRoot.set(workspaceRoot)
}.filter { it.isNotEmpty() }

val cargoToml = objects.fileProperty()
cargoToml.set(File(workspaceRoot, "Cargo.toml"))
val cargoWorkspaceVersion = providers.fileContents(cargoToml).asText
    .map { parseCargoWorkspaceVersion(it)?.trim().orEmpty() }
    .filter { it.isNotEmpty() }

val tunnetVersionName = injectedReleaseVersion
    .orElse(gitDescribeVersion)
    .orElse(cargoWorkspaceVersion)
    .map { stripTagPrefix(it.trim()) }
    .orElse(devPlaceholderVersionName)

val tunnetVersionCode = tunnetVersionName.zip(injectedReleaseVersion.orElse("")) { name, injected ->
    versionCodeOf(name)?.takeIf { it > 0 } ?: run {
        if (injected.isNotEmpty()) {
            throw GradleException(
                "TUNNET_VERSION=$injected cannot be folded into a versionCode, so this " +
                    "release APK could not be sequenced as an update. Tag a clean triple (e.g. " +
                    "`v0.9.0`); sequencing pre-release tags is deliberately not designed.",
            )
        }
        devPlaceholderVersionCode
    }
}

android {
    namespace = "io.tunnet.android"
    compileSdk {
        version = release(37) {
            minorApiLevel = 0
        }
    }
    ndkVersion = NDK_VERSION

    defaultConfig {
        applicationId = "io.tunnet.android"
        minSdk = 26
        targetSdk = 37
        versionCode = tunnetVersionCode.get()
        versionName = tunnetVersionName.get()
    }

    signingConfigs {
        val keystorePath: String? = System.getenv("ANDROID_KEYSTORE_PATH")
        if (keystorePath != null) {
            create("release") {
                storeFile = file(keystorePath)
                storePassword = System.getenv("ANDROID_KEYSTORE_PASSWORD")
                keyAlias = System.getenv("ANDROID_KEY_ALIAS")
                keyPassword = System.getenv("ANDROID_KEY_PASSWORD")
            }
        }
    }

    buildTypes {
        getByName("debug") {
            isMinifyEnabled = false
            ndk { abiFilters += debugAbis }
        }
        getByName("release") {
            isMinifyEnabled = false
            signingConfig = signingConfigs.findByName("release")
            ndk { abiFilters += releaseAbis }
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    buildFeatures {
        compose = true
    }
    lint {
        abortOnError = true
        checkReleaseBuilds = false
        // Phone/VPN distribution is arm64; debug also ships x86_64 for emulators.
        disable += "ChromeOsAbiSupport"
    }
}

protobuf {
    protoc {
        artifact = "com.google.protobuf:protoc:4.36.1"
    }
    generateProtoTasks {
        all().forEach { task ->
            task.builtins {
                create("java") {
                    option("lite")
                }
            }
        }
    }
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2026.08.00")
    implementation(composeBom)
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    debugImplementation("androidx.compose.ui:ui-tooling")
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.11.0")
    implementation("androidx.core:core-ktx:1.19.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.11.0")
    implementation("com.google.protobuf:protobuf-javalite:4.36.1")
    testImplementation("junit:junit:4.13.2")
}

fun androidSdkDir(): File {
    val env = System.getenv("ANDROID_HOME")
        ?: System.getenv("ANDROID_SDK_ROOT")
    if (env != null) {
        val dir = File(env)
        if (dir.isDirectory) return dir
    }
    val props = rootProject.file("local.properties")
    if (props.isFile) {
        val sdk = props.readLines()
            .firstOrNull { it.trim().startsWith("sdk.dir=") }
            ?.substringAfter("=")
            ?.trim()
            ?.replace("\\\\", "\\")
        if (sdk != null) {
            val dir = File(sdk)
            if (dir.isDirectory) return dir
        }
    }
    throw GradleException("ANDROID_HOME / ANDROID_SDK_ROOT is not set and local.properties has no sdk.dir")
}

fun pinnedNdkHome(): File {
    val pinned = File(androidSdkDir(), "ndk/$NDK_VERSION")
    if (pinned.isDirectory) return pinned
    val env = System.getenv("ANDROID_NDK_HOME")?.let(::File)
    if (env != null && env.isDirectory) {
        val revision = File(env, "source.properties")
            .takeIf { it.isFile }
            ?.readLines()
            ?.firstOrNull { it.startsWith("Pkg.Revision") }
            ?.substringAfter("=")
            ?.trim()
        if (revision == NDK_VERSION) return env
        throw GradleException(
            "ANDROID_NDK_HOME=${env.path} is NDK $revision; this project pins $NDK_VERSION. " +
                "Install ndk;$NDK_VERSION or point ANDROID_NDK_HOME at that revision.",
        )
    }
    return pinned
}

val rustInputs = files(
    fileTree(workspaceRoot) {
        include(
            "Cargo.toml",
            "Cargo.lock",
            "rust-toolchain.toml",
            "crates/**/*.rs",
            "crates/**/Cargo.toml",
            "proto/**/*.proto",
        )
        exclude("**/target/**")
    },
)

androidComponents {
    onVariants { variant ->
        val release = variant.buildType == "release"
        val abis = if (release) releaseAbis else debugAbis
        val taskName = "cargoNdk${variant.name.replaceFirstChar { it.uppercase() }}"
        val cargo = tasks.register<CargoNdkBuild>(taskName) {
            group = "rust"
            description = "Build $AGENT_CRATE for the ${variant.name} variant via cargo-ndk."
            crate.set(AGENT_CRATE)
            cargoRelease.set(release)
            platform.set(NDK_PLATFORM)
            ndkHome.set(pinnedNdkHome().absolutePath)
            ndkVersion.set(NDK_VERSION)
            cargoNdkVersion.set(CARGO_NDK_VERSION)
            this.abis.set(abis)
            repoRoot.set(workspaceRoot)
            outDir.set(layout.buildDirectory.dir("rustJniLibs/${variant.name}"))
            rustSources.from(rustInputs)
        }
        variant.sources.jniLibs?.addGeneratedSourceDirectory(cargo, CargoNdkBuild::outDir)
    }
}

val syncAgentSchema = tasks.register<Copy>("syncAgentSchema") {
    group = "protobuf"
    description = "Stage proto/tunnet into src/main/proto for the protobuf plugin."
    from(File(workspaceRoot, "proto"))
    into(layout.projectDirectory.dir("src/main/proto"))
}

tasks.matching { it.name.contains("Proto") }.configureEach {
    dependsOn(syncAgentSchema)
}
