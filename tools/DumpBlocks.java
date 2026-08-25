import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * Report the basic-block graph Ghidra's decompiler ends up with.
 *
 * The C output shows which constructs were recovered but not the graph they were
 * recovered from. When our structuring disagrees with Ghidra's, the question is
 * whether the graphs differ or only the rules, and this answers it: per block,
 * the address range, the in and out edge counts, and the terminating opcode.
 */
public class DumpBlocks extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] scriptArgs = getScriptArgs();
        if (scriptArgs.length < 2) {
            throw new IllegalArgumentException("usage: DumpBlocks.java <function> <output>");
        }
        Address entry = currentProgram.getAddressFactory().getAddress(scriptArgs[0]);
        Function function = getFunctionAt(entry);
        if (function == null) {
            function = createFunction(entry, null);
        }
        if (function == null) {
            throw new IllegalStateException("no function at " + scriptArgs[0]);
        }
        DecompInterface decompiler = new DecompInterface();
        DecompileOptions options = new DecompileOptions();
        decompiler.setOptions(options);
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(true);
        if (!decompiler.openProgram(currentProgram)) {
            throw new IllegalStateException("cannot open program: " + decompiler.getLastMessage());
        }
        DecompileResults results = decompiler.decompileFunction(function, 120, monitor);
        HighFunction high = results.getHighFunction();
        if (high == null) {
            throw new IllegalStateException("no high function: " + results.getErrorMessage());
        }
        List<String> lines = new ArrayList<>();
        Iterator<PcodeBlockBasic> blocks = high.getBasicBlocks().iterator();
        while (blocks.hasNext()) {
            PcodeBlockBasic block = blocks.next();
            StringBuilder line = new StringBuilder();
            line.append("block ").append(block.getIndex());
            line.append(" start=").append(block.getStart());
            line.append(" stop=").append(block.getStop());
            line.append(" in=").append(block.getInSize());
            line.append(" out=").append(block.getOutSize());
            for (int i = 0; i < block.getOutSize(); ++i) {
                line.append(" out").append(i).append("=").append(block.getOut(i).getIndex());
            }
            for (int i = 0; i < block.getInSize(); ++i) {
                line.append(" in").append(i).append("=").append(block.getIn(i).getIndex());
            }
            PcodeOp last = null;
            Iterator<PcodeOp> ops = block.getIterator();
            while (ops.hasNext()) {
                last = ops.next();
            }
            if (last != null) {
                line.append(" last=").append(last.getMnemonic());
            }
            lines.add(line.toString());
        }
        try (PrintWriter writer = new PrintWriter(scriptArgs[1], "UTF-8")) {
            for (String line : lines) {
                writer.println(line);
            }
        }
        decompiler.dispose();
        println("DumpBlocks wrote " + lines.size() + " blocks");
    }
}
