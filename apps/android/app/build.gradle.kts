import org.gradle.api.file.ConfigurableFileCollection
import org.gradle.internal.os.OperatingSystem
import org.gradle.process.ExecOperations
import javax.inject.Inject

plugins {
    id("com.android.application")
    kotlin("android")
    kotlin("plugin.compose")
}

// ---------------------------------------------------------------------------
// Version, from the release tag.
//
// Android sequences updates on a strictly increasing integer `versionCode`, so
// a hardcoded one makes every release look like the same build to a device and
// it can never be offered as an in-place update. The version is therefore READ
// from the release tag rather than minted here, in precedence order:
//
//   1. `TUNNET_VERSION`, exported by CI from the tag.
//   2. `git describe --tags --always`, for an informative local dev build.
//   3. The workspace Cargo version, the last resort (no git, source tarball).
//
// Every lookup is failure-tolerant, because a dev APK on a placeholder version
// beats a dev build that fails. That tolerance stops at the release path: an
// INJECTED version that cannot be folded into a versionCode fails the build,
// since a signed release carrying versionCode 1 is exactly the unsequenceable
// artifact this block exists to prevent.
// ---------------------------------------------------------------------------

/** Repo root: `apps/android/app` -> `apps/android` -> `apps` -> root. */
val workspaceRoot: File = rootProject.projectDir.parentFile.parentFile

val devPlaceholderVersionCode = 1
val devPlaceholderVersionName = "0.0.0"

/** The version CI injected from the tag; the dev-versus-release distinction. */
val injectedReleaseVersion: String? =
    System.getenv("TUNNET_VERSION")?.trim()?.takeIf { it.isNotEmpty() }

fun gitDescribe(): String? = try {
    val process = ProcessBuilder("git", "describe", "--tags", "--always")
        .directory(workspaceRoot)
        .redirectError(ProcessBuilder.Redirect.DISCARD)
        .start()
    val described = process.inputStream.bufferedReader().use { it.readText() }.trim()
    if (process.waitFor() == 0 && described.isNotEmpty()) described else null
} catch (e: Exception) {
    null
}

val cargoVersionLine = Regex("^version\\s*=\\s*\"([^\"]+)\"")

/** `[workspace.package] version` from the root Cargo.toml. */
fun cargoWorkspaceVersion(): String? = try {
    val lines = File(workspaceRoot, "Cargo.toml").readLines()
    val start = lines.indexOfFirst { it.trim() == "[workspace.package]" }
    if (start < 0) {
        null
    } else {
        lines.drop(start + 1)
            .takeWhile { !it.trim().startsWith("[") }
            .firstNotNullOfOrNull { cargoVersionLine.find(it.trim()) }
            ?.groupValues?.get(1)
    }
} catch (e: Exception) {
    null
}

/** `v0.9.0` -> `0.9.0`, leaving anything else untouched. */
fun stripTagPrefix(version: String): String =
    if (version.length > 1 && version[0] == 'v' && version[1].isDigit()) version.substring(1) else version

fun resolveTunnetVersion(): String? {
    val resolved = listOf(injectedReleaseVersion, gitDescribe(), cargoWorkspaceVersion())
        .firstOrNull { !it.isNullOrBlank() }
        ?.trim()
        ?: return null
    return stripTagPrefix(resolved)
}

/**
 * Fold a semver triple into one monotonic integer:
 * `major * 10000 + minor * 100 + patch` (`0.9.0` -> 900, `1.0.0` -> 10000).
 *
 * `null` for anything that is not a clean triple (a `git describe` suffix, a
 * pre-release tag), because those are not released versions. A minor or patch
 * above 99 would collide with the next minor/major and silently break update
 * sequencing, so that fails loudly instead.
 */
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

val resolvedTunnetVersion: String? = resolveTunnetVersion()
val tunnetVersionName: String = resolvedTunnetVersion ?: devPlaceholderVersionName
val tunnetVersionCode: Int = versionCodeOf(tunnetVersionName)?.takeIf { it > 0 } ?: run {
    if (injectedReleaseVersion != null) {
        throw GradleException(
            "TUNNET_VERSION=$injectedReleaseVersion cannot be folded into a versionCode, so this " +
                "release APK could not be sequenced as an update. Tag a clean triple (e.g. " +
                "`v0.9.0`); sequencing pre-release tags is deliberately not designed.",
        )
    }
    devPlaceholderVersionCode
}

android {
    namespace = "io.tunnet.android"
    compileSdk = 36

    defaultConfig {
        // Must match the JNI export names in crates/tunnet-mobile/src/jni_bridge.rs
        // (`Java_io_tunnet_android_TunnetNative_*`).
        applicationId = "io.tunnet.android"
        // 26 is where Android's background execution limits begin. Going lower
        // would mean maintaining a second service lifecycle model; everything
        // above it is a single version branch.
        minSdk = 26
        targetSdk = 36
        versionCode = tunnetVersionCode
        versionName = tunnetVersionName
        // arm64-v8a for real devices, x86_64 for the emulator.
        ndk { abiFilters += listOf("arm64-v8a", "x86_64") }
    }

    // ---- Release signing: CI-only, gated on env presence -------------------
    //
    // The keystore and credentials arrive ONLY through the environment. With no
    // ANDROID_KEYSTORE_PATH the release signing config is never created, the
    // release build type gets a null signingConfig, and AGP emits
    // `app-release-unsigned.apk` — so an unsigned build can never masquerade as
    // a signed one. Nothing about the signing identity is committed: a release
    // key cannot be regenerated.
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
        }
        getByName("release") {
            // No R8: the signed APK is the same code the debug APK carries, one
            // fewer variable between what is tested and what users install.
            isMinifyEnabled = false
            signingConfig = signingConfigs.findByName("release")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    // The modern replacement for the deprecated `kotlinOptions {}` block.
    kotlin {
        compilerOptions {
            jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
        }
    }
    buildFeatures {
        compose = true
    }

    // Where cargoBuildAgent stages the cross-compiled agent.
    sourceSets["main"].jniLibs.srcDir(layout.buildDirectory.dir("rustJniLibs"))
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2024.09.03")
    implementation(composeBom)
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    debugImplementation("androidx.compose.ui:ui-tooling")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.7")
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
}

// ---------------------------------------------------------------------------
// Cross-compile the Tunnet agent as a normal Gradle step.
//
// A `cargo build` per ABI, linked with the NDK's clang, producing
// libtunnet_mobile.so staged into jniLibs. Wired into `preBuild`, so a plain
// `./gradlew :app:assembleDebug` builds the agent and packages it with no
// manual step and no cargo-ndk dependency.
// ---------------------------------------------------------------------------

val agentCrate = "tunnet-mobile"
val agentLib = "libtunnet_mobile.so"

/** Android ABI -> Rust target triple. */
val targetAbis = mapOf(
    "arm64-v8a" to "aarch64-linux-android",
    "x86_64" to "x86_64-linux-android",
)

/** NDK API level for the clang linker wrappers; matches the minSdk floor. */
val targetNdkApiLevel = 26

fun ndkDir(): File {
    val explicit = System.getenv("ANDROID_NDK_HOME")
    if (explicit != null && File(explicit).isDirectory) return File(explicit)

    val sdk = System.getenv("ANDROID_HOME")
        ?: System.getenv("ANDROID_SDK_ROOT")
        ?: rootProject.file("local.properties")
            .takeIf { it.isFile }
            ?.let { file ->
                file.readLines()
                    .firstOrNull { it.trim().startsWith("sdk.dir=") }
                    ?.substringAfter("sdk.dir=")
                    ?.trim()
            }
        ?: throw GradleException("ANDROID_HOME / ANDROID_SDK_ROOT is not set and local.properties has no sdk.dir")

    val ndkParent = File(sdk, "ndk")
    return ndkParent.listFiles()?.filter { it.isDirectory }?.maxByOrNull { it.name }
        ?: throw GradleException("no NDK found under $ndkParent")
}

fun ndkBinDir(): File {
    val hostTag = when {
        OperatingSystem.current().isMacOsX -> "darwin-x86_64"
        OperatingSystem.current().isWindows -> "windows-x86_64"
        else -> "linux-x86_64"
    }
    return File(ndkDir(), "toolchains/llvm/prebuilt/$hostTag/bin")
}

abstract class CargoBuildAgent @Inject constructor(private val exec: ExecOperations) : DefaultTask() {
    @get:Internal abstract val repoRoot: DirectoryProperty
    @get:Internal abstract val ndkBin: DirectoryProperty
    @get:Input abstract val crate: Property<String>
    @get:Input abstract val libName: Property<String>
    @get:Input abstract val ndkApiLevel: Property<Int>
    @get:Input abstract val abis: MapProperty<String, String>
    @get:OutputDirectory abstract val outDir: DirectoryProperty

    /**
     * The Rust sources, so this task is NOT "up to date" after a Rust edit.
     *
     * Without this the task's only @Inputs were static strings, so Gradle
     * happily repackaged a STALE .so after a code change — the agent fix in
     * the library silently missing from the APK. The whole workspace is
     * tracked (Cargo.lock, manifests, sources) because cargo's own incremental
     * build makes re-running this cheap; correctness beats a 12-minute cache.
     */
    /**
     * The Rust sources, so this task is NOT "up to date" after a Rust edit.
     *
     * Without this the task's only @Inputs were static strings, so Gradle
     * happily repackaged a STALE .so after a code change — the agent fix in
     * the library silently missing from the APK. The whole workspace is
     * tracked (Cargo.lock, manifests, sources) because cargo's own incremental
     * build makes re-running this cheap; correctness beats a 12-minute cache.
     * Abstract because values are wired at registration, not construction.
     */
    @get:InputFiles
    abstract val rustSources: ConfigurableFileCollection

    @TaskAction
    fun run() {
        val bin = ndkBin.get().asFile
        val root = repoRoot.get().asFile
        val api = ndkApiLevel.get()
        val lib = libName.get()

        abis.get().forEach { (abi, triple) ->
            // The NDK ships one clang wrapper per (arch, API level); its name is
            // the triple with the API level appended, e.g.
            // aarch64-linux-android26-clang.
            val archPrefix = triple.removeSuffix("-linux-android")
            val cc = File(bin, "$archPrefix-linux-android$api-clang")
            if (!cc.isFile) {
                throw GradleException("NDK clang wrapper not found: $cc")
            }
            val ar = File(bin, "llvm-ar")
            val envSuffix = triple.replace('-', '_')

            exec.exec {
                workingDir = root
                environment("CC_$envSuffix", cc.absolutePath)
                environment("AR_$envSuffix", ar.absolutePath)
                environment(
                    "CARGO_TARGET_${triple.uppercase().replace('-', '_')}_LINKER",
                    cc.absolutePath,
                )
                commandLine("cargo", "build", "--release", "-p", crate.get(), "--target", triple)
            }

            val built = File(root, "target/$triple/release/$lib")
            if (!built.isFile) {
                throw GradleException("expected $built after cargo build for $abi")
            }
            val dest = outDir.get().dir(abi).asFile
            dest.mkdirs()
            built.copyTo(File(dest, lib), overwrite = true)
        }
    }
}

val cargoBuildAgent by tasks.registering(CargoBuildAgent::class) {
    group = "rust"
    description = "Cross-compile the Tunnet agent ($agentLib) for the floor ABIs."
    repoRoot.set(workspaceRoot)
    ndkBin.set(ndkBinDir())
    crate.set(agentCrate)
    libName.set(agentLib)
    ndkApiLevel.set(targetNdkApiLevel)
    abis.set(targetAbis)
    outDir.set(layout.buildDirectory.dir("rustJniLibs"))
    rustSources.from(
        run {
            workspaceRoot.resolve("crates")
                .walkTopDown()
                .filter { it.isFile && (it.extension == "rs" || it.name == "Cargo.toml") }
                .toList()
        },
        workspaceRoot.resolve("Cargo.toml"),
        workspaceRoot.resolve("Cargo.lock"),
    )
}

tasks.named("preBuild") {
    dependsOn(cargoBuildAgent)
}
