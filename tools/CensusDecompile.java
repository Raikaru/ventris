import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.FunctionPrototype;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighFunctionDBUtil.ReturnCommitOption;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import java.io.File;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * Exports many Ghidra-decompiled functions from one imported program.
 *
 * <p>DumpDecompile.java pins a single checked-in fixture. This script serves the
 * quality census: it reuses one import and one decompiler for every requested
 * function, and records a per-function failure instead of aborting the batch, so
 * one unsupported function cannot hide the rest of the measurement.
 *
 * <p>Each spec line is {@code id<TAB>function-or-address<TAB>length}, where a
 * length of {@code -} lets Ghidra determine the function body.
 */
public class CensusDecompile extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] scriptArgs = getScriptArgs();
        if (scriptArgs.length < 2) {
            throw new IllegalArgumentException(
                    "usage: CensusDecompile.java <specfile> <outputdir>");
        }
        Path specPath = Path.of(scriptArgs[0]);
        File outputDir = new File(scriptArgs[1]);
        outputDir.mkdirs();

        DecompInterface decompiler = new DecompInterface();
        try {
            DecompileOptions options = new DecompileOptions();
            decompiler.setOptions(options);
            decompiler.toggleCCode(true);
            decompiler.toggleSyntaxTree(true);
            if (!decompiler.openProgram(currentProgram)) {
                throw new IllegalStateException(
                        "cannot open decompiler: " + decompiler.getLastMessage());
            }
            for (String line : Files.readAllLines(specPath, StandardCharsets.UTF_8)) {
                String spec = line.trim();
                if (spec.isEmpty() || spec.startsWith("#")) {
                    continue;
                }
                String[] fields = spec.split("\t", -1);
                if (fields.length < 3) {
                    throw new IllegalArgumentException("malformed spec line: " + spec);
                }
                String id = fields[0];
                Long explicitLength = "-".equals(fields[2]) ? null : Long.decode(fields[2]);
                try {
                    exportOne(
                            decompiler,
                            fields[1],
                            explicitLength,
                            new File(outputDir, id + ".ghidra-decompile"));
                    println("VENTRIS census ok id=" + id);
                }
                catch (Exception error) {
                    String message = error.getClass().getSimpleName() + ": " + error.getMessage();
                    try (PrintWriter writer =
                            new PrintWriter(new File(outputDir, id + ".error"), "UTF-8")) {
                        writer.print(message);
                    }
                    println("VENTRIS census fail id=" + id + " error=" + message);
                }
            }
            println("VENTRIS census done");
        }
        finally {
            decompiler.dispose();
        }
    }

    private void exportOne(
            DecompInterface decompiler, String wanted, Long explicitLength, File output)
            throws Exception {
        Function function = findOrCreateFunction(wanted, explicitLength);
        if (function == null) {
            throw new IllegalStateException("no candidate function " + wanted);
        }
        DecompileResults results = decompile(decompiler, function);
        primeDirectCallees(decompiler, results);
        decompiler.flushCache();
        results = decompile(decompiler, function);
        commitPrototype(function, results.getHighFunction());
        decompiler.flushCache();
        results = decompile(decompiler, function);
        HighFunction high = results.getHighFunction();

        StringBuilder text = new StringBuilder();
        text.append("format ventris-ghidra-decompile-1\n");
        text.append("function ").append(function.getName()).append('\n');
        text.append("language ")
                .append(currentProgram.getLanguage().getLanguageID()).append('\n');
        text.append("compiler ")
                .append(currentProgram.getCompilerSpec().getCompilerSpecID()).append('\n');
        text.append("entry ").append(function.getEntryPoint().getOffset()).append('\n');
        text.append("length ").append(function.getBody().getNumAddresses()).append('\n');

        FunctionPrototype prototype = high.getFunctionPrototype();
        text.append("return ").append(typeName(prototype.getReturnType())).append('\n');
        ParameterDefinition[] parameters = prototype.getParameterDefinitions();
        int parameterCount = parameters == null ? 0 : parameters.length;
        text.append("params ").append(parameterCount).append('\n');
        for (int index = 0; index < parameterCount; index++) {
            text.append("param ").append(index).append(' ')
                    .append(typeName(parameters[index].getDataType())).append('\n');
        }

        List<String> calls = new ArrayList<>();
        Iterator<PcodeOpAST> operations = high.getPcodeOps();
        while (operations != null && operations.hasNext()) {
            PcodeOpAST operation = operations.next();
            if (operation.getOpcode() != PcodeOp.CALL
                    && operation.getOpcode() != PcodeOp.CALLIND) {
                continue;
            }
            calls.add("call "
                    + operation.getSeqnum().getTarget().getOffset() + ' '
                    + operation.getMnemonic() + ' '
                    + varnodeText(operation.getInput(0)) + ' '
                    + Math.max(0, operation.getNumInputs() - 1));
        }
        text.append("calls ").append(calls.size()).append('\n');
        for (String call : calls) {
            text.append(call).append('\n');
        }

        String c = results.getDecompiledFunction().getC()
                .replace("\r\n", "\n").replace('\r', '\n');
        text.append("c_begin\n");
        for (String line : c.split("\n", -1)) {
            text.append(stripTrailingWhitespace(line)).append('\n');
        }
        text.append("c_end\n");

        File parent = output.getParentFile();
        if (parent != null) {
            parent.mkdirs();
        }
        try (PrintWriter writer = new PrintWriter(output, "UTF-8")) {
            writer.print(text.toString());
        }
    }

    private DecompileResults decompile(DecompInterface decompiler, Function function) {
        DecompileResults results = decompiler.decompileFunction(function, 120, monitor);
        if (!results.decompileCompleted()) {
            throw new IllegalStateException(
                    "decompilation failed: " + results.getErrorMessage());
        }
        if (results.getHighFunction() == null) {
            throw new IllegalStateException("decompiler returned no HighFunction");
        }
        return results;
    }

    private void primeDirectCallees(
            DecompInterface decompiler, DecompileResults callerResults) {
        Iterator<PcodeOpAST> operations = callerResults.getHighFunction().getPcodeOps();
        while (operations != null && operations.hasNext()) {
            PcodeOpAST operation = operations.next();
            if (operation.getOpcode() != PcodeOp.CALL || operation.getNumInputs() == 0) {
                continue;
            }
            Function callee = currentProgram.getFunctionManager()
                    .getFunctionAt(operation.getInput(0).getAddress());
            if (callee == null || callee.isThunk() || callee.isExternal()) {
                continue;
            }
            commitPrototype(callee, decompile(decompiler, callee).getHighFunction());
        }
    }

    private static void commitPrototype(Function function, HighFunction high) {
        try {
            HighFunctionDBUtil.commitParamsToDatabase(
                    high, true, ReturnCommitOption.COMMIT, SourceType.ANALYSIS);
        }
        catch (DuplicateNameException | InvalidInputException error) {
            throw new IllegalStateException(
                    "cannot commit inferred prototype for " + function.getEntryPoint(),
                    error);
        }
    }

    private Function findOrCreateFunction(String wanted, Long explicitLength) throws Exception {
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        while (functions.hasNext()) {
            Function function = functions.next();
            boolean matches = function.getName().equals(wanted);
            if (!matches) {
                try {
                    matches = function.getEntryPoint().getOffset()
                            == Long.decode(wanted).longValue();
                }
                catch (NumberFormatException ignored) {
                    // The requested function is symbolic.
                }
            }
            if (matches && !function.isThunk() && !function.isExternal()) {
                return function;
            }
        }

        Address start = toAddr(wanted);
        if (explicitLength == null) {
            disassemble(start);
            return createFunction(start, null);
        }
        if (explicitLength.longValue() <= 0) {
            throw new IllegalArgumentException("explicit length must be positive");
        }
        AddressSet body = new AddressSet(start, start.addNoWrap(explicitLength.longValue() - 1));
        Address cursor = start;
        while (body.contains(cursor)) {
            Instruction instruction = currentProgram.getListing().getInstructionAt(cursor);
            if (instruction == null) {
                DisassembleCommand command = new DisassembleCommand(cursor, body, false);
                command.applyTo(currentProgram, monitor);
                instruction = currentProgram.getListing().getInstructionAt(cursor);
            }
            if (instruction == null) {
                throw new IllegalStateException("failed to disassemble instruction at " + cursor);
            }
            cursor = instruction.getMaxAddress().next();
        }
        return currentProgram.getFunctionManager().createFunction(
                null, start, body, SourceType.USER_DEFINED);
    }

    private static String varnodeText(Varnode varnode) {
        if (varnode == null) {
            return "void";
        }
        Address address = varnode.getAddress();
        return address.getAddressSpace().getName() + ":"
                + Long.toUnsignedString(address.getOffset()) + ":" + varnode.getSize();
    }

    private static String typeName(DataType type) {
        return type == null ? "unknown" : type.getDisplayName().replace(' ', '_');
    }

    private static String stripTrailingWhitespace(String value) {
        int end = value.length();
        while (end > 0 && Character.isWhitespace(value.charAt(end - 1))) {
            end--;
        }
        return value.substring(0, end);
    }
}
