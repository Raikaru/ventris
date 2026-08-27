import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.pcode.FunctionPrototype;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighFunctionDBUtil.ReturnCommitOption;
import ghidra.program.model.symbol.SourceType;
import java.io.File;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

/**
 * Exports every function Ghidra found in one program, up to a bound.
 *
 * <p>CensusDecompile.java serves the pinned corpus: the caller names each
 * function, so the measurement inherits whichever functions a human chose. This
 * script removes that selection bias - it enumerates the program's own function
 * list and exports a bounded prefix of it, so the resulting sample is "what
 * Ghidra found in this image" rather than "what someone thought worth pinning".
 *
 * <p>The oracle here is Ghidra analysed headless, its recovered prototype
 * committed, then decompiled. It deliberately omits CensusDecompile's callee
 * priming pass, which decompiles every direct callee to sharpen the caller's
 * argument recovery: that costs a decompilation per edge and is affordable for
 * tens of functions, not thousands. Both scripts emit the same
 * {@code ventris-ghidra-decompile-1} format so one comparator reads either.
 *
 * <p>Arguments are {@code <outputdir> <max> <minbytes> <maxbytes>}. Functions
 * outside the byte range are skipped: below it sit thunks and single-jump stubs
 * that agree trivially and would inflate any score, above it sit a handful of
 * outliers whose decompilation dominates the wall clock.
 */
public class CensusSweep extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] scriptArgs = getScriptArgs();
        if (scriptArgs.length < 4) {
            throw new IllegalArgumentException(
                    "usage: CensusSweep.java <outputdir> <max> <minbytes> <maxbytes>");
        }
        File outputDir = new File(scriptArgs[0]);
        int max = Integer.parseInt(scriptArgs[1]);
        long minBytes = Long.parseLong(scriptArgs[2]);
        long maxBytes = Long.parseLong(scriptArgs[3]);
        outputDir.mkdirs();

        List<Function> candidates = new ArrayList<>();
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        while (functions.hasNext()) {
            Function function = functions.next();
            if (function.isThunk() || function.isExternal()) {
                continue;
            }
            long length = function.getBody().getNumAddresses();
            if (length < minBytes || length > maxBytes) {
                continue;
            }
            candidates.add(function);
            if (candidates.size() >= max) {
                break;
            }
        }
        println("VENTRIS sweep candidates=" + candidates.size());

        DecompInterface decompiler = new DecompInterface();
        StringBuilder manifest = new StringBuilder();
        int exported = 0;
        int failed = 0;
        try {
            decompiler.setOptions(new DecompileOptions());
            decompiler.toggleCCode(true);
            decompiler.toggleSyntaxTree(true);
            if (!decompiler.openProgram(currentProgram)) {
                throw new IllegalStateException(
                        "cannot open decompiler: " + decompiler.getLastMessage());
            }
            for (Function function : candidates) {
                String id = identifier(function);
                try {
                    exportOne(decompiler, function, new File(outputDir, id + ".ghidra-decompile"));
                    manifest.append(id).append('\t')
                            .append(function.getName()).append('\t')
                            .append("0x").append(Long.toHexString(
                                    function.getEntryPoint().getOffset())).append('\t')
                            .append(function.getBody().getNumAddresses()).append('\n');
                    exported++;
                }
                catch (Exception error) {
                    failed++;
                    String message = error.getClass().getSimpleName() + ": " + error.getMessage();
                    try (PrintWriter writer =
                            new PrintWriter(new File(outputDir, id + ".error"), "UTF-8")) {
                        writer.print(message);
                    }
                }
            }
            try (PrintWriter writer =
                    new PrintWriter(new File(outputDir, "sweep-manifest.tsv"), "UTF-8")) {
                writer.print(manifest.toString());
            }
            println("VENTRIS sweep exported=" + exported + " failed=" + failed);
            println("VENTRIS sweep done");
        }
        finally {
            decompiler.dispose();
        }
    }

    /** A filesystem-safe per-function key that stays stable across runs. */
    private static String identifier(Function function) {
        return "fn_" + Long.toHexString(function.getEntryPoint().getOffset());
    }

    private void exportOne(DecompInterface decompiler, Function function, File output)
            throws Exception {
        DecompileResults results = decompiler.decompileFunction(function, 120, monitor);
        if (results == null || !results.decompileCompleted()) {
            throw new IllegalStateException(
                    "decompilation failed: "
                            + (results == null ? "no results" : results.getErrorMessage()));
        }
        HighFunction high = results.getHighFunction();
        if (high == null) {
            throw new IllegalStateException("no high function");
        }
        try {
            HighFunctionDBUtil.commitParamsToDatabase(
                    high, true, ReturnCommitOption.COMMIT, SourceType.ANALYSIS);
            decompiler.flushCache();
            DecompileResults second = decompiler.decompileFunction(function, 120, monitor);
            if (second != null && second.decompileCompleted()
                    && second.getHighFunction() != null) {
                results = second;
                high = second.getHighFunction();
            }
        }
        catch (Exception ignored) {
            // A prototype that will not commit is not a reason to drop the function;
            // the first decompilation is still a faithful oracle for it.
        }

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
