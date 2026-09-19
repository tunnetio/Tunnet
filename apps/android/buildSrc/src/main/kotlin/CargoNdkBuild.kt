import org.gradle.api.DefaultTask
import org.gradle.api.file.ConfigurableFileCollection
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.provider.ListProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputFiles
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.TaskAction
import org.gradle.process.ExecOperations
import java.io.File
import javax.inject.Inject

abstract class CargoNdkBuild @Inject constructor(
    private val exec: ExecOperations,
) : DefaultTask() {
    @get:Input abstract val crate: Property<String>
    @get:Input abstract val cargoRelease: Property<Boolean>
    @get:Input abstract val platform: Property<Int>
    @get:Input abstract val ndkHome: Property<String>
    @get:Input abstract val ndkVersion: Property<String>
    @get:Input abstract val cargoNdkVersion: Property<String>
    @get:Input abstract val abis: ListProperty<String>
    @get:Internal abstract val repoRoot: DirectoryProperty

    @get:InputFiles
    abstract val rustSources: ConfigurableFileCollection

    @get:OutputDirectory
    abstract val outDir: DirectoryProperty

    @TaskAction
    fun run() {
        val ndk = File(ndkHome.get())
        val version = ndkVersion.get()
        if (!ndk.isDirectory) {
            throw org.gradle.api.GradleException(
                "NDK $version not found at ${ndk.path}. Install it with " +
                    "sdkmanager \"ndk;$version\" and do not point ANDROID_NDK_HOME at another revision.",
            )
        }
        val cargo = resolveOnPath("cargo")
            ?: throw org.gradle.api.GradleException("cargo is not on PATH")
        val dest = outDir.get().asFile
        dest.deleteRecursively()
        dest.mkdirs()

        val args = mutableListOf(
            cargo.absolutePath,
            "ndk",
            "--platform",
            platform.get().toString(),
            "-o",
            dest.absolutePath,
        )
        abis.get().forEach { abi ->
            args += listOf("-t", abi)
        }
        args += listOf("build", "-p", crate.get())
        if (cargoRelease.get()) {
            args += "--release"
        }

        val result = exec.exec {
            workingDir = repoRoot.get().asFile
            environment("ANDROID_NDK_HOME", ndk.absolutePath)
            commandLine(args)
            isIgnoreExitValue = true
        }
        if (result.exitValue == 0) {
            return
        }
        val probe = exec.exec {
            workingDir = repoRoot.get().asFile
            commandLine(cargo.absolutePath, "ndk", "--version")
            isIgnoreExitValue = true
        }
        if (probe.exitValue != 0) {
            throw org.gradle.api.GradleException(
                "cargo-ndk is required to build the Android agent. Install " +
                    "`cargo install cargo-ndk --version ${cargoNdkVersion.get()} --locked`.",
            )
        }
        throw org.gradle.api.GradleException("cargo ndk failed with exit ${result.exitValue}")
    }
}

fun resolveOnPath(name: String): File? {
    val ext = if (System.getProperty("os.name").lowercase().contains("windows")) {
        listOf("", ".exe", ".cmd", ".bat")
    } else {
        listOf("")
    }
    val dirs = System.getenv("PATH")?.split(File.pathSeparator).orEmpty()
    for (dir in dirs) {
        for (suffix in ext) {
            val candidate = File(dir, name + suffix)
            if (candidate.isFile) return candidate
        }
    }
    return null
}
