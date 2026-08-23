import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import java.io.File;
import java.io.PrintWriter;
import java.util.List;

/** Export one analyzed function as a stable text-only Ghidra p-code capsule. */
public class DumpCapsule extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] scriptArgs = getScriptArgs();
        String wanted = scriptArgs.length > 0 ? scriptArgs[0] : "FUN_140001460";
        String outputPath = scriptArgs.length > 1
                ? scriptArgs[1]
                : new File(System.getProperty("java.io.tmpdir"), "ventris/capsule/capsule.txt").getPath();

        Function pick = null;
        FunctionIterator fit = currentProgram.getFunctionManager().getFunctions(true);
        while (fit.hasNext()) {
            Function function = fit.next();
            boolean match = function.getName().equals(wanted);
            if (!match) {
                try {
                    match = function.getEntryPoint().getOffset() == Long.decode(wanted).longValue();
                } catch (NumberFormatException ignored) {
                    // The argument is a symbolic function name.
                }
            }
            if (!function.isThunk() && !function.isExternal() && match) {
                pick = function;
                break;
            }
        }

        if (pick == null) {
            try {
                Address start = toAddr(wanted);
                disassemble(start);
                pick = createFunction(start, null);
            } catch (Exception ignored) {
                // A symbolic query without an auto-discovered function remains absent.
            }
        }
        if (pick == null) {
            println("VENTRIS no candidate " + wanted);
            return;
        }

        StringBuilder output = new StringBuilder();
        long entry = pick.getEntryPoint().getOffset();
        long length = pick.getBody().getNumAddresses();
        output.append("function ").append(pick.getName()).append('\n');
        output.append("language ").append(currentProgram.getLanguage().getLanguageID()).append('\n');
        output.append("entry ").append(entry).append('\n');
        output.append("length ").append(length).append('\n');

        byte[] bytes = new byte[(int) length];
        currentProgram.getMemory().getBytes(pick.getEntryPoint(), bytes);
        output.append("bytes ");
        for (byte value : bytes) {
            output.append(String.format("%02x", value & 0xff));
        }
        output.append('\n');

        InstructionIterator instructions =
                currentProgram.getListing().getInstructions(pick.getBody(), true);
        while (instructions.hasNext()) {
            Instruction instruction = instructions.next();
            PcodeOp[] operations = instruction.getPcode();
            output.append("inst ").append(instruction.getAddress().getOffset())
                    .append(' ').append(instruction.getLength())
                    .append(' ').append(operations.length)
                    .append("  # ").append(instruction).append('\n');
            for (PcodeOp operation : operations) {
                output.append("  op ").append(operation.getOpcode());
                appendVarnode(output, operation.getOutput());
                for (int index = 0; index < operation.getNumInputs(); index++) {
                    appendVarnode(output, operation.getInput(index));
                }
                output.append('\n');
            }
        }

        Language language = currentProgram.getLanguage();
        List<Register> registers = language.getRegisters();
        for (Register register : registers) {
            output.append("reg ").append(register.getName())
                    .append(' ').append(register.getAddress().getAddressSpace().getName())
                    .append(' ').append(register.getAddress().getOffset())
                    .append(' ').append(register.getMinimumByteSize()).append('\n');
        }
        int userOpCount = language.getNumberOfUserDefinedOpNames();
        for (int index = 0; index < userOpCount; index++) {
            output.append("userop ").append(index).append(' ')
                    .append(language.getUserDefinedOpName(index)).append('\n');
        }

        File file = new File(outputPath);
        File parent = file.getParentFile();
        if (parent != null) {
            parent.mkdirs();
        }
        try (PrintWriter writer = new PrintWriter(file, "UTF-8")) {
            writer.print(output.toString());
        }
        println("VENTRIS capsule function=" + pick.getName()
                + " entry=" + Long.toHexString(entry)
                + " len=" + length
                + " registers=" + registers.size()
                + " userops=" + userOpCount);
        println("VENTRIS done");
    }

    private static void appendVarnode(StringBuilder output, Varnode varnode) {
        if (varnode == null) {
            output.append(" void");
            return;
        }
        Address address = varnode.getAddress();
        output.append(' ').append(address.getAddressSpace().getName())
                .append(':').append(address.getOffset())
                .append(':').append(varnode.getSize());
    }
}
