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
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import java.io.File;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/** Export one Ghidra-decompiled function as a deterministic stage oracle. */
public class DumpDecompile extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] scriptArgs = getScriptArgs();
        if (scriptArgs.length < 2) {
            throw new IllegalArgumentException(
                    "usage: DumpDecompile.java <function> <output> [length]");
        }
        String wanted = scriptArgs[0];
        String outputPath = scriptArgs[1];
        Long explicitLength = scriptArgs.length > 2 ? Long.decode(scriptArgs[2]) : null;
        Function function = findOrCreateFunction(wanted, explicitLength);
        if (function == null) {
            throw new IllegalStateException("no candidate function " + wanted);
        }

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
            DecompileResults results = decompile(decompiler, function);
            primeDirectCallees(decompiler, results);
            decompiler.flushCache();
            results = decompile(decompiler, function);
            commitPrototype(function, results.getHighFunction());
            decompiler.flushCache();
            results = decompile(decompiler, function);
            HighFunction high = results.getHighFunction();

            StringBuilder output = new StringBuilder();
            output.append("format ventris-ghidra-decompile-1\n");
            output.append("function ").append(function.getName()).append('\n');
            output.append("language ")
                    .append(currentProgram.getLanguage().getLanguageID()).append('\n');
            output.append("compiler ")
                    .append(currentProgram.getCompilerSpec().getCompilerSpecID()).append('\n');
            output.append("entry ").append(function.getEntryPoint().getOffset()).append('\n');
            output.append("length ").append(function.getBody().getNumAddresses()).append('\n');
            output.append("bytes ").append(functionBytes(function)).append('\n');

            FunctionPrototype prototype = high.getFunctionPrototype();
            DataType returnType = prototype.getReturnType();
            output.append("return ").append(typeName(returnType)).append('\n');
            ParameterDefinition[] parameters = prototype.getParameterDefinitions();
            int parameterCount = parameters == null ? 0 : parameters.length;
            output.append("params ").append(parameterCount).append('\n');
            if (parameters != null) {
                for (int index = 0; index < parameters.length; index++) {
                    ParameterDefinition parameter = parameters[index];
                    output.append("param ").append(index).append(' ')
                            .append(typeName(parameter.getDataType())).append('\n');
                }
            }

            List<String> calls = new ArrayList<>();
            Iterator<PcodeOpAST> operations = high.getPcodeOps();
            while (operations != null && operations.hasNext()) {
                PcodeOpAST operation = operations.next();
                if (operation.getOpcode() != PcodeOp.CALL &&
                        operation.getOpcode() != PcodeOp.CALLIND) {
                    continue;
                }
                StringBuilder call = new StringBuilder();
                call.append("call ")
                        .append(operation.getSeqnum().getTarget().getOffset()).append(' ')
                        .append(operation.getMnemonic()).append(' ');
                Varnode destination = operation.getInput(0);
                call.append(varnodeText(destination)).append(' ')
                        .append(Math.max(0, operation.getNumInputs() - 1));
                for (int index = 1; index < operation.getNumInputs(); index++) {
                    Varnode input = operation.getInput(index);
                    call.append(' ').append(varnodeType(input));
                }
                calls.add(call.toString());
            }
            output.append("calls ").append(calls.size()).append('\n');
            for (String call : calls) {
                output.append(call).append('\n');
            }

            String c = results.getDecompiledFunction().getC()
                    .replace("\r\n", "\n").replace('\r', '\n');
            output.append("c_begin\n");
            for (String line : c.split("\n", -1)) {
                output.append(stripTrailingWhitespace(line)).append('\n');
            }
            output.append("c_end\n");

            File file = new File(outputPath);
            File parent = file.getParentFile();
            if (parent != null) {
                parent.mkdirs();
            }
            try (PrintWriter writer = new PrintWriter(file, "UTF-8")) {
                writer.print(output.toString());
            }
            println("VENTRIS decompile function=" + function.getName()
                    + " entry=" + Long.toHexString(function.getEntryPoint().getOffset())
                    + " params=" + parameterCount + " calls=" + calls.size());
            println("VENTRIS done");
        }
        finally {
            decompiler.dispose();
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
            DecompileResults calleeResults = decompile(decompiler, callee);
            commitPrototype(callee, calleeResults.getHighFunction());
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
                    matches = function.getEntryPoint().getOffset() == Long.decode(wanted).longValue();
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

    private String functionBytes(Function function) throws Exception {
        long length = function.getBody().getNumAddresses();
        if (length > Integer.MAX_VALUE) {
            throw new IllegalStateException("function body is too large to export");
        }
        byte[] bytes = new byte[(int) length];
        int read = currentProgram.getMemory().getBytes(function.getEntryPoint(), bytes);
        if (read != bytes.length) {
            throw new IllegalStateException(
                    "read " + read + " of " + bytes.length + " function bytes");
        }
        StringBuilder hex = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) {
            hex.append(String.format("%02x", value & 0xff));
        }
        return hex.toString();
    }

    private static String varnodeText(Varnode varnode) {
        if (varnode == null) {
            return "void";
        }
        Address address = varnode.getAddress();
        return address.getAddressSpace().getName() + ":" +
                Long.toUnsignedString(address.getOffset()) + ":" + varnode.getSize();
    }

    private static String varnodeType(Varnode varnode) {
        HighVariable high = varnode.getHigh();
        return high == null ? "unknown" : typeName(high.getDataType());
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
