/* ###
 * Service launch options, parsed before any Ghidra machinery starts.
 */
package net.ventris;

import java.nio.file.Files;
import java.nio.file.Path;

/** Parsed command line for the service process. */
public final class ServiceOptions {
    /** Ghidra installation directory; sets the ghidra.install.dir property. */
    public final Path installDir;
    /** Directory holding the Ghidra project; created if missing. */
    public final Path projectDir;
    /** Ghidra project name inside projectDir. */
    public final String projectName;

    private ServiceOptions(Path installDir, Path projectDir, String projectName) {
        this.installDir = installDir;
        this.projectDir = projectDir;
        this.projectName = projectName;
    }

    public static ServiceOptions fromArgs(String[] args) {
        Path installDir = null;
        Path projectDir = Path.of(System.getProperty("java.io.tmpdir"), "ventris-projects");
        String projectName = "ventris";
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--install-dir" -> installDir = Path.of(requireValue(args, ++i, "--install-dir"));
                case "--project-dir" -> projectDir = Path.of(requireValue(args, ++i, "--project-dir"));
                case "--project-name" -> projectName = requireValue(args, ++i, "--project-name");
                default -> throw new IllegalArgumentException("unknown argument: " + args[i]);
            }
        }
        if (installDir == null) {
            throw new IllegalArgumentException("--install-dir is required");
        }
        if (!Files.isDirectory(installDir)) {
            throw new IllegalArgumentException("not a directory: " + installDir);
        }
        return new ServiceOptions(installDir.toAbsolutePath(), projectDir.toAbsolutePath(), projectName);
    }

    private static String requireValue(String[] args, int index, String flag) {
        if (index >= args.length) {
            throw new IllegalArgumentException(flag + " needs a value");
        }
        return args[index];
    }
}
