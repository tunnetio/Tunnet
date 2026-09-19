import org.gradle.api.file.DirectoryProperty
import org.gradle.api.provider.ValueSource
import org.gradle.api.provider.ValueSourceParameters
import org.gradle.process.ExecOperations
import java.io.ByteArrayOutputStream
import javax.inject.Inject

abstract class GitDescribe : ValueSource<String, GitDescribe.Params> {
    abstract class Params : ValueSourceParameters {
        abstract val repoRoot: DirectoryProperty
    }

    @get:Inject
    abstract val execOperations: ExecOperations

    override fun obtain(): String {
        val output = ByteArrayOutputStream()
        return try {
            val result = execOperations.exec {
                commandLine("git", "describe", "--tags", "--always")
                workingDir = parameters.repoRoot.get().asFile
                standardOutput = output
                errorOutput = ByteArrayOutputStream()
                isIgnoreExitValue = true
            }
            val described = output.toString(Charsets.UTF_8).trim()
            if (result.exitValue == 0 && described.isNotEmpty()) described else ""
        } catch (_: Exception) {
            ""
        }
    }
}
