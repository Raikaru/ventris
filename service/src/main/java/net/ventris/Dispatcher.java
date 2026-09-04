/* ###
 * RPC method dispatch: the Core API's Java-backed half.
 *
 * Methods (all take "session"; addresses are Ghidra address strings):
 *   import   {session, path}            -> {program, functions: N}
 *   open     {session, program}         -> {program, functions: N}
 *   functions{session}                  -> [{name, entry, size}]
 *   function {session, address}         -> {name, entry, size, signature?}
 *   symbols  {session}                  -> [{name, address, external, source}]
 *   read_memory {session, address, size}-> {bytes: base64}
 *   xrefs_to {session, address}         -> [{from, type}]
 *   xrefs_from {session, address}       -> [{to, type}]
 *   rename   {session, address, name}   -> {ok: true}
 *   decompile{session, address}         -> {code}
 *   disassemble {session, address, n}   -> [{address, text}]
 */
package net.ventris;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.app.plugin.processors.sleigh.UniqueLayout;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/** Translates JSON requests into Ghidra calls and the answers back. */
final class Dispatcher {
    private final GhidraBootstrap ghidra;

    Dispatcher(ServiceOptions options) throws IOException,
            ghidra.util.exception.NotFoundException, ghidra.util.NotOwnerException,
            ghidra.framework.store.LockException {
        this.ghidra = new GhidraBootstrap(options);
    }

    JsonElement dispatch(JsonObject request, JsonElement id) {
        JsonElement methodEl = request.get("method");
        if (methodEl == null || !methodEl.isJsonPrimitive()) {
            throw new Main.RpcError(-32600, "missing string method");
        }
        String method = methodEl.getAsString();
        JsonObject params = request.has("params") && request.get("params").isJsonObject()
            ? request.getAsJsonObject("params")
            : new JsonObject();
        return switch (method) {
            case "import" -> importProgram(params);
            case "export_facts" -> exportFacts(params);
            case "open" -> openProgram(params);
            case "close" -> closeSession(params);
            case "functions" -> listFunctions(params);
            case "function" -> describeFunction(params);
            case "symbols" -> listSymbols(params);
            case "read_memory" -> readMemory(params);
            case "xrefs_to" -> xrefsTo(params);
            case "xrefs_from" -> xrefsFrom(params);
            case "rename" -> rename(params);
            case "decompile" -> decompile(params);
            case "disassemble" -> disassemble(params);
            case "dump_specs" -> dumpSpecs(params);
            case "ping" -> ping();
            case "shutdown" -> shutdownNow();
            default -> throw new Main.RpcError(-32601, "unknown method: " + method);
        };
    }

    /** Closes every session, then exits the JVM (EOF path does the same). */
    private JsonElement shutdownNow() {
        ghidra.shutdown();
        System.exit(0);
        return null; // unreachable
    }

    void shutdown() {
        ghidra.shutdown();
    }

    // ---- methods ---------------------------------------------------------

    private JsonElement ping() {
        JsonObject out = new JsonObject();
        out.addProperty("pong", true);
        return out;
    }

    private JsonElement importProgram(JsonObject params) {
        String sessionId = requireString(params, "session");
        String path = requireString(params, "path");
        Path binary = Path.of(path);
        if (!java.nio.file.Files.isRegularFile(binary)) {
            throw new Main.RpcError(-32004, "not a file: " + path);
        }
        try {
            Session session = ghidra.importAndAnalyze(sessionId, binary);
            JsonObject out = new JsonObject();
            out.addProperty("program", session.programName());
            out.addProperty("language", session.program().getLanguageID().getIdAsString());
            // Program.getImageBase(): .ghidra-java/ghidra/program/model/listing/Program.java:473-477.
            out.addProperty("image_base", session.program().getImageBase().toString());
            out.addProperty("functions", session.functionEntries().size());
            return out;
        } catch (IOException | ghidra.util.exception.CancelledException
                | ghidra.util.exception.VersionException
                | ghidra.util.InvalidNameException e) {
            throw new Main.RpcError(-32005, "import failed: " + e.getMessage());
        }
    }

    private JsonElement openProgram(JsonObject params) {
        String sessionId = requireString(params, "session");
        String programName = requireString(params, "program");
        try {
            Session session = ghidra.open(sessionId, programName);
            JsonObject out = new JsonObject();
            out.addProperty("program", session.programName());
            out.addProperty("language", session.program().getLanguageID().getIdAsString());
            out.addProperty("functions", session.functionEntries().size());
            return out;
        } catch (IOException e) {
            throw new Main.RpcError(-32005, "open failed: " + e.getMessage());
        }
    }

    private JsonElement closeSession(JsonObject params) {
        ghidra.closeSession(requireString(params, "session"));
        JsonObject out = new JsonObject();
        out.addProperty("ok", true);
        return out;
    }

    private JsonElement listFunctions(JsonObject params) {
        Session session = ghidra.session(requireString(params, "session"));
        JsonArray arr = new JsonArray();
        for (Address entry : session.functionEntries()) {
            Function f = session.functionAt(entry);
            JsonObject o = new JsonObject();
            o.addProperty("name", f.getName());
            o.addProperty("entry", entry.toString());
            o.addProperty("size", f.getBody().getNumAddresses());
            arr.add(o);
        }
        return arr;
    }

    /**
     * Batched export: functions, symbols, and every outgoing xref of every
     * function body in ONE response. Fifteen separate RPC round-trips each
     * paid Ghidra's per-query overhead; batching removes ~14 of them.
     */
    private JsonElement exportFacts(JsonObject params) {
        Session session = ghidra.session(requireString(params, "session"));
        JsonObject out = new JsonObject();

        JsonArray funcs = new JsonArray();
        for (Address entry : session.functionEntries()) {
            Function f = session.functionAt(entry);
            JsonObject o = new JsonObject();
            o.addProperty("name", f.getName());
            o.addProperty("entry", entry.toString());
            o.addProperty("size", f.getBody().getNumAddresses());
            funcs.add(o);
        }
        out.add("functions", funcs);

        JsonArray xrefs = new JsonArray();
        for (Address entry : session.functionEntries()) {
            Function f = session.functionAt(entry);
            ghidra.program.model.address.AddressIterator it =
                f.getBody().getAddresses(true);
            while (it.hasNext()) {
                Address a = it.next();
                for (Reference r : session.program().getReferenceManager().getReferencesFrom(a)) {
                    JsonObject o = new JsonObject();
                    o.addProperty("from", r.getFromAddress().toString());
                    o.addProperty("to", r.getToAddress().toString());
                    o.addProperty("kind", r.getReferenceType().toString());
                    xrefs.add(o);
                }
            }
        }
        out.add("xrefs", xrefs);

        JsonArray comments = new JsonArray();
        ghidra.program.model.listing.Listing listing =
            session.program().getListing();
        java.util.Set<Integer> commentKinds = new java.util.LinkedHashSet<>();
        commentKinds.add(CodeUnit.EOL_COMMENT);
        commentKinds.add(CodeUnit.PRE_COMMENT);
        commentKinds.add(CodeUnit.PLATE_COMMENT);
        for (Address entry : session.functionEntries()) {
            Function f = session.functionAt(entry);
            ghidra.program.model.address.AddressIterator cit =
                listing.getCommentAddressIterator(f.getBody(), true);
            while (cit.hasNext()) {
                CodeUnit cu = listing.getCodeUnitAt(cit.next());
                if (cu == null) {
                    // Iterator can yield addresses with no code unit (e.g.
                    // data chunks inside a function body); skipping is the
                    // honest behavior — the NPE used to abort the import.
                    continue;
                }
                for (int kind : commentKinds) {
                    String text = cu.getComment(kind);
                    if (text != null && text.length() != 0) {
                        JsonObject o = new JsonObject();
                        String typeName = "eol";
                        if (kind == CodeUnit.PRE_COMMENT) {
                            typeName = "pre";
                        }
                        o.addProperty("address", cu.getAddress().toString());
                        o.addProperty("function", entry.toString());
                        o.addProperty("kind", typeName);
                        o.addProperty("text", text);
                        comments.add(o);
                    }
                }
            }
        }
        out.add("comments", comments);

        JsonArray types = new JsonArray();
        ghidra.program.model.data.DataTypeManager dtm =
            session.program().getDataTypeManager();
        java.util.Iterator<ghidra.program.model.data.DataType> typeIt =
            dtm.getAllDataTypes();
        while (typeIt.hasNext()) {
            ghidra.program.model.data.DataType dt = typeIt.next();
            if (dt instanceof ghidra.program.model.data.Pointer) {
                continue;
            }
            JsonObject o = new JsonObject();
            o.addProperty("name", dt.getName());
            o.addProperty("definition", dt.getDescription());
            types.add(o);
        }
        out.add("types", types);
        return out;
    }

    /**
     * All outgoing references from a function body: walks every instruction
     * address in the body and collects its outgoing edges. A function entry
     * query alone misses calls originating mid-body (e.g. the call inside
     * main), which is what the exporter needs.
     */
    private JsonElement functionXrefsFrom(JsonObject params) {
        Session session = ghidra.session(requireString(params, "session"));
        Address at = session.address(requireString(params, "address"));
        Function f = session.functionAt(at);
        JsonArray arr = new JsonArray();
        ghidra.program.model.address.AddressIterator it =
            f.getBody().getAddresses(true);
        while (it.hasNext()) {
            Address a = it.next();
            for (Reference r : session.program().getReferenceManager().getReferencesFrom(a)) {
                JsonObject o = new JsonObject();
                o.addProperty("from", r.getFromAddress().toString());
                o.addProperty("to", r.getToAddress().toString());
                o.addProperty("kind", r.getReferenceType().toString());
                arr.add(o);
            }
        }
        return arr;
    }

    private JsonElement describeFunction(JsonObject params) {
        Session session = ghidra.session(requireString(params, "session"));
        Address at = session.address(requireString(params, "address"));
        Function f = session.functionAt(at);
        JsonObject o = new JsonObject();
        o.addProperty("name", f.getName());
        o.addProperty("entry", f.getEntryPoint().toString());
        o.addProperty("size", f.getBody().getNumAddresses());
        o.addProperty("signature", f.getSignature().getPrototypeString(true));
        o.addProperty("calling_convention", f.getCallingConventionName());
        return o;
    }

    private JsonElement listSymbols(JsonObject params) {
        Session session = ghidra.session(requireString(params, "session"));
        JsonArray arr = new JsonArray();
        SymbolIterator it = session.program().getSymbolTable().getAllSymbols(true);
        for (Symbol s : it) {
            JsonObject o = new JsonObject();
            o.addProperty("name", s.getName());
            o.addProperty("address", s.getAddress().toString());
            o.addProperty("external", s.isExternal());
            o.addProperty("source", s.getSource().toString());
            arr.add(o);
        }
        return arr;
    }

    private JsonElement readMemory(JsonObject params) {
        Session session = ghidra.session(requireString(params, "session"));
        Address at = session.address(requireString(params, "address"));
        int size = requireInt(params, "size");
        if (size <= 0 || size > 1 << 20) {
            throw new Main.RpcError(-32006, "size out of range: " + size);
        }
        byte[] buf = new byte[size];
        int got;
        try {
            got = session.program().getMemory().getBytes(at, buf);
        } catch (MemoryAccessException e) {
            throw new Main.RpcError(-32007, "unreadable memory at " + at + ": " + e.getMessage());
        }
        JsonObject out = new JsonObject();
        out.addProperty("bytes", Base64.getEncoder().encodeToString(java.util.Arrays.copyOf(buf, got)));
        out.addProperty("read", got);
        return out;
    }

    private JsonElement xrefsTo(JsonObject params) {
        Session session = ghidra.session(requireString(params, "session"));
        Address at = session.address(requireString(params, "address"));
        JsonArray arr = new JsonArray();
        for (Reference r : session.program().getReferenceManager().getReferencesTo(at)) {
            JsonObject o = new JsonObject();
            o.addProperty("from", r.getFromAddress().toString());
            o.addProperty("kind", r.getReferenceType().toString());
            arr.add(o);
        }
        return arr;
    }

    private JsonElement xrefsFrom(JsonObject params) {
        Session session = ghidra.session(requireString(params, "session"));
        Address at = session.address(requireString(params, "address"));
        JsonArray arr = new JsonArray();
        for (Reference r : session.program().getReferenceManager().getReferencesFrom(at)) {
            JsonObject o = new JsonObject();
            o.addProperty("to", r.getToAddress().toString());
            o.addProperty("kind", r.getReferenceType().toString());
            arr.add(o);
        }
        return arr;
    }

    private JsonElement rename(JsonObject params) {
        Session session = ghidra.session(requireString(params, "session"));
        Address at = session.address(requireString(params, "address"));
        String name = requireString(params, "name");
        Function f = session.functionAt(at);
        int tx = session.program().startTransaction("Rename");
        try {
            try {
                f.setName(name, SourceType.USER_DEFINED);
            } catch (ghidra.util.exception.DuplicateNameException
                    | ghidra.util.exception.InvalidInputException e) {
                throw new Main.RpcError(-32008, "rename failed: " + e.getMessage());
            }
        } finally {
            session.program().endTransaction(tx, true);
        }
        JsonObject out = new JsonObject();
        out.addProperty("ok", true);
        return out;
    }

    private JsonElement decompile(JsonObject params) {
        Session session = ghidra.session(requireString(params, "session"));
        Address at = session.address(requireString(params, "address"));
        Function f = session.functionAt(at);
        DecompInterface decompiler = new DecompInterface();
        try {
            if (!decompiler.openProgram(session.program())) {
                throw new Main.RpcError(-32009, "decompiler refused to open program");
            }
            DecompileResults r = decompiler.decompileFunction(f, 120, ghidra.monitor());
            if (!r.decompileCompleted()) {
                throw new Main.RpcError(-32010,
                    "decompile failed at " + at + ": " + r.getErrorMessage());
            }
            JsonObject out = new JsonObject();
            out.addProperty("code", r.getDecompiledFunction().getC());
            return out;
        } finally {
            decompiler.dispose();
        }
    }

    private JsonElement disassemble(JsonObject params) {
        Session session = ghidra.session(requireString(params, "session"));
        Address at = session.address(requireString(params, "address"));
        int n = params.has("n") && params.get("n").isJsonPrimitive()
            ? params.get("n").getAsInt() : 32;
        JsonArray arr = new JsonArray();
        InstructionIterator it = session.program().getListing().getInstructions(at, true);
        while (it.hasNext() && n-- > 0) {
            Instruction ins = it.next();
            JsonObject o = new JsonObject();
            o.addProperty("address", ins.getAddress().toString());
            o.addProperty("text", ins.toString());
            arr.add(o);
        }
        return arr;
    }

    // ---- param helpers ---------------------------------------------------

    private static String requireString(JsonObject params, String key) {
        JsonElement el = params.get(key);
        if (el == null || !el.isJsonPrimitive()) {
            throw new Main.RpcError(-32602, "missing string param: " + key);
        }
        return el.getAsString();
    }

    private static int requireInt(JsonObject params, String key) {
        JsonElement el = params.get(key);
        if (el == null || !el.isJsonPrimitive()) {
            throw new Main.RpcError(-32602, "missing int param: " + key);
        }
        return el.getAsInt();
    }

    /**
     * Captures the four spec documents exactly as DecompInterface.registerProgram
     * sends them (pspec, cspec, tspec, coretypes) and writes them under outdir so
     * the native worker can replay them without a JVM. A migration aid, not part
     * of the supported surface.
     */
    private JsonElement dumpSpecs(JsonObject params) {
        Session session = ghidra.session(requireString(params, "session"));
        String outDir = requireString(params, "outdir");
        try {
            java.nio.file.Files.createDirectories(java.nio.file.Path.of(outDir));
            Program program = session.program();
            ghidra.app.plugin.processors.sleigh.SleighLanguage lang =
                (ghidra.app.plugin.processors.sleigh.SleighLanguage) program.getLanguage();
            ghidra.program.model.lang.CompilerSpec cspec = program.getCompilerSpec();
            long uniqueBase =
                UniqueLayout.SLEIGH_BASE.getOffset(lang);

            ghidra.program.model.lang.SleighLanguageDescription desc =
                (ghidra.program.model.lang.SleighLanguageDescription) lang.getLanguageDescription();
            java.nio.file.Files.writeString(
                java.nio.file.Path.of(outDir, "pspec.xml"),
                java.nio.file.Files.readString(java.nio.file.Path.of(desc.getSpecFile().getAbsolutePath())));

            ghidra.program.model.pcode.XmlEncode xe =
                new ghidra.program.model.pcode.XmlEncode(false);
            cspec.encode(xe);
            java.nio.file.Files.writeString(
                java.nio.file.Path.of(outDir, "cspec.xml"), xe.toString());

            ghidra.program.model.pcode.XmlEncode te =
                new ghidra.program.model.pcode.XmlEncode(false);
            lang.encodeTranslator(te, program.getAddressFactory(), uniqueBase);
            java.nio.file.Files.writeString(
                java.nio.file.Path.of(outDir, "tspec.xml"), te.toString());

            ghidra.program.model.pcode.XmlEncode ce =
                new ghidra.program.model.pcode.XmlEncode(false);
            ghidra.program.model.pcode.PcodeDataTypeManager cdtm =
                new ghidra.program.model.pcode.PcodeDataTypeManager(program, null);
            cdtm.encodeCoreTypes(ce);
            java.nio.file.Files.writeString(
                java.nio.file.Path.of(outDir, "coretypes.xml"), ce.toString());

            // Register table: name -> (space index, offset, size) for the
            // worker's getregister callback.
            StringBuilder regs = new StringBuilder();
            for (ghidra.program.model.lang.Register reg : program.getLanguage().getRegisters()) {
                regs.append(reg.getName()).append('\t')
                    .append(reg.getAddress().getOffset())
                    .append('\t').append(reg.getMinimumByteSize()).append('\n');
            }
            java.nio.file.Files.writeString(
                java.nio.file.Path.of(outDir, "registers.txt"), regs.toString());

            JsonObject out = new JsonObject();
            out.addProperty("ok", true);
            out.addProperty("outdir", outDir);
            return out;
        } catch (Exception e) {
            throw new Main.RpcError(-32011, "dump_specs failed: " + e);
        }
    }
}
