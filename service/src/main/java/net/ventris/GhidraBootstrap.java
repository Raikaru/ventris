/* ###
 * Ghidra bootstrap: application initialization and program lifecycle.
 *
 * Every call here mirrors a pattern taken from Ghidra's own headless analyzer
 * (ghidra/app/util/headless/HeadlessAnalyzer.java in .ghidra-java/) because
 * the obvious-looking alternatives do not work:
 *
 * - Application.initializeApplication is mandatory before any GhidraProject
 *   call; without it ToolChestImpl dies in Application.checkAppInitialized.
 * - Import goes through ProgramLoader and persists with Loaded.save; the
 *   deprecated GhidraProject.importProgram hands back a Program backed by a
 *   DomainFileProxy whose save throws ReadOnlyException.
 * - Analysis must run inside an open DB transaction; AutoAnalysisManager
 *   writes StoredAnalyzerTimes at the end and NoTransactionException escapes
 *   otherwise.
 */
package net.ventris;

import ghidra.GhidraApplicationLayout;
import ghidra.app.util.importer.ProgramLoader;
import ghidra.app.util.opinion.LoadResults;
import ghidra.app.util.opinion.Loaded;
import ghidra.base.project.GhidraProject;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;
import ghidra.util.task.ConsoleTaskMonitor;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

/** Owns the GhidraProject and the set of open programs. */
final class GhidraBootstrap {
    private final ServiceOptions options;
    private final ConsoleTaskMonitor monitor = new ConsoleTaskMonitor();
    private final java.util.Map<String, Session> sessions = new java.util.HashMap<>();
    private GhidraProject project;
    ConsoleTaskMonitor monitor() {
        return monitor;
    }

    /** The consumer under which openProgram-acquired programs are held. */
    Object projectConsumer() {
        return project;
    }




    GhidraBootstrap(ServiceOptions options) throws IOException,
            ghidra.util.exception.NotFoundException, ghidra.util.NotOwnerException,
            ghidra.framework.store.LockException {
        this.options = options;
        System.setProperty("ghidra.install.dir", options.installDir.toString());
        HeadlessGhidraApplicationConfiguration config = new HeadlessGhidraApplicationConfiguration();
        config.setInitializeLogging(false);
        Application.initializeApplication(new GhidraApplicationLayout(), config);
        Files.createDirectories(options.projectDir);
        java.io.File gpr = options.projectDir.resolve(options.projectName + ".gpr").toFile();
        this.project = gpr.isFile()
            ? GhidraProject.openProject(options.projectDir.toString(), options.projectName, true)
            : GhidraProject.createProject(options.projectDir.toString(), options.projectName, false);
    }

    /**
     * Imports a binary under a client-chosen session id, analyzes it, and
     * saves it into the project. Re-importing the same id replaces it.
     */
    Session importAndAnalyze(String sessionId, Path binary) throws IOException,
            ghidra.util.exception.CancelledException, ghidra.util.exception.VersionException,
            ghidra.util.InvalidNameException {
        closeSession(sessionId);
        try (LoadResults<Program> loadResults = ProgramLoader.builder()
            .source(binary.toFile())
            .project(project.getProject())
            .monitor(monitor)
            .load()) {
            Loaded<Program> primary = loadResults.getPrimary();
            Program program = primary.getDomainObject(this);
            int tx = program.startTransaction("Analysis");
            try {
                project.analyze(program);
            } finally {
                program.endTransaction(tx, true);
            }
            DomainFile domainFile = primary.save(monitor);
            String name = domainFile.getName();
            Session session = new Session(sessionId, name, domainFile, program, this);
            sessions.put(sessionId, session);
            return session;
        }
    }

    /** Opens an already-saved program by project file name. */
    Session open(String sessionId, String programName) throws IOException {
        closeSession(sessionId);
        // GhidraProject.openProgram composes folderPath + "/" + name; an empty
        // folderPath yields the root path "/name" that projectData.getFile requires.
        Program program = project.openProgram("", programName, false);
        Session session = new Session(sessionId, programName, null, program, this);
        sessions.put(sessionId, session);
        return session;
    }

    Session session(String sessionId) {
        Session session = sessions.get(sessionId);
        if (session == null) {
            throw new Main.RpcError(-32001, "unknown session: " + sessionId);
        }
        return session;
    }

    void closeSession(String sessionId) {
        Session session = sessions.remove(sessionId);
        if (session != null) {
            session.close();
        }
    }

    void shutdown() {
        for (String id : Map.copyOf(sessions).keySet()) {
            closeSession(id);
        }
        // GhidraProject.close() releases every program in openPrograms with
        // the project itself as consumer (GhidraProject.java:239-249), but
        // import-flow programs register the bootstrap consumer instead —
        // that release throws "unknown consumer". The process exit releases
        // the project file lock anyway, so closing the project here only
        // risks the exception.
        project = null;
    }
}
