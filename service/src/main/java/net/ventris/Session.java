/* ###
 * One open program bound to a client session id.
 */
package net.ventris;

import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Function;
import ghidra.program.model.address.Address;

import java.util.List;

/** A session-scoped Ghidra program plus the accessors the RPC surface needs. */
final class Session {
    private final String id;
    private final String programName;
    private final DomainFile domainFile;
    private final Program program;
    private final GhidraBootstrap owner;

    Session(String id, String programName, DomainFile domainFile, Program program,
            GhidraBootstrap owner) {
        this.id = id;
        this.programName = programName;
        this.domainFile = domainFile;
        this.program = program;
        this.owner = owner;
    }

    String id() {
        return id;
    }

    String programName() {
        return programName;
    }

    Program program() {
        return program;
    }

    /** Resolves a client address string ("00401000", "ram:1000") or fails. */
    Address address(String text) {
        Address at = program.getAddressFactory().getAddress(text);
        if (at == null) {
            throw new Main.RpcError(-32002, "bad address: " + text);
        }
        return at;
    }

    /** Entry points of every function, in address order. */
    java.util.List<Address> functionEntries() {
        java.util.List<Address> out = new java.util.ArrayList<>();
        ghidra.program.model.listing.FunctionIterator it =
            program.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            out.add(it.next().getEntryPoint());
        }
        return out;
    }

    Function functionAt(Address entry) {
        Function f = program.getFunctionManager().getFunctionAt(entry);
        if (f == null) {
            throw new Main.RpcError(-32003, "no function at " + entry);
        }
        return f;
    }

    /**
     * Releases the program. Lifecycle is owned by GhidraBootstrap.closeSession;
     * this only performs the consumer release.
     */
    void close() {
        // Programs obtained via GhidraProject.openProgram are consumed by the
        // project itself; import flow programs are consumed by the bootstrap.
        // Releasing with the wrong consumer throws IllegalArgumentException.
        try {
            if (domainFile == null) {
                program.release(owner.projectConsumer());
            } else {
                program.release(owner);
            }
        } catch (RuntimeException e) {
            System.err.println("ventris-service: release failed for " + id + ": " + e);
        }
    }
}
