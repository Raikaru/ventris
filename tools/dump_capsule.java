// Dump a self-contained "environment capsule" for one real function:
// bytes, per-instruction p-code, and the register map. This is what ventris's
// own client will serve to decompile.exe over the callback protocol.
ghidra.app.plugin.processors.sleigh.SleighLanguage slang =
        (ghidra.app.plugin.processors.sleigh.SleighLanguage) currentProgram.getLanguage();
ghidra.program.model.listing.Listing listing = currentProgram.getListing();

String[] scriptArgs = getScriptArgs();
String wanted = scriptArgs.length > 0 ? scriptArgs[0] : "FUN_140001460";
String outputPath = scriptArgs.length > 1
        ? scriptArgs[1]
        : new java.io.File(System.getProperty("java.io.tmpdir"), "ventris/capsule/capsule.txt").getPath();

ghidra.program.model.listing.Function pick = null;
ghidra.program.model.listing.FunctionIterator fit =
        currentProgram.getFunctionManager().getFunctions(true);
while (fit.hasNext()) {
    ghidra.program.model.listing.Function g = fit.next();
    boolean match = g.getName().equals(wanted);
    if (!match) {
        try {
            match = g.getEntryPoint().getOffset() == Long.decode(wanted).longValue();
        } catch (NumberFormatException ignored) {
            // The argument is a symbolic function name.
        }
    }
    if (g.isThunk() || g.isExternal() || !match) continue;
    pick = g;
    break;
}
if (pick == null) {
    try {
        ghidra.program.model.address.Address start = toAddr(wanted);
        disassemble(start);
        pick = createFunction(start, null);
    } catch (Exception ignored) {
        // A symbolic query without an auto-discovered function remains absent.
    }
}
if (pick == null) { println("VENTRIS no candidate " + wanted); return; }

java.io.File output = new java.io.File(outputPath);
java.io.File parent = output.getParentFile();
if (parent != null) parent.mkdirs();
StringBuilder sb = new StringBuilder();
long entry = pick.getEntryPoint().getOffset();
long len = pick.getBody().getNumAddresses();
sb.append("function ").append(pick.getName()).append('\n');
sb.append("language ").append(currentProgram.getLanguage().getLanguageID()).append('\n');
sb.append("entry ").append(entry).append('\n');
sb.append("length ").append(len).append('\n');

// raw bytes of the body
byte[] buf = new byte[(int) len];
currentProgram.getMemory().getBytes(pick.getEntryPoint(), buf);
sb.append("bytes ");
for (int i = 0; i < buf.length; i++) {
    sb.append(String.format("%02x", buf[i] & 0xff));
}
sb.append('\n');

// p-code per instruction
ghidra.program.model.listing.InstructionIterator iit =
        listing.getInstructions(pick.getBody(), true);
while (iit.hasNext()) {
    ghidra.program.model.listing.Instruction ins = iit.next();
    ghidra.program.model.pcode.PcodeOp[] ops = ins.getPcode();
    sb.append("inst ").append(ins.getAddress().getOffset())
      .append(' ').append(ins.getLength())
      .append(' ').append(ops.length)
      .append("  # ").append(ins.toString()).append('\n');
    for (int i = 0; i < ops.length; i++) {
        ghidra.program.model.pcode.PcodeOp o = ops[i];
        sb.append("  op ").append(o.getOpcode());
        ghidra.program.model.pcode.Varnode out = o.getOutput();
        if (out == null) {
            sb.append(" void");
        } else {
            sb.append(' ').append(out.getAddress().getAddressSpace().getName())
              .append(':').append(out.getOffset()).append(':').append(out.getSize());
        }
        for (int j = 0; j < o.getNumInputs(); j++) {
            ghidra.program.model.pcode.Varnode v = o.getInput(j);
            sb.append(' ').append(v.getAddress().getAddressSpace().getName())
              .append(':').append(v.getOffset()).append(':').append(v.getSize());
        }
        sb.append('\n');
    }
}

// register map: every register the cspec or p-code can name
java.util.List<ghidra.program.model.lang.Register> regs = slang.getRegisters();
for (int i = 0; i < regs.size(); i++) {
    ghidra.program.model.lang.Register r = regs.get(i);
    sb.append("reg ").append(r.getName())
      .append(' ').append(r.getAddress().getAddressSpace().getName())
      .append(' ').append(r.getAddress().getOffset())
      .append(' ').append(r.getMinimumByteSize()).append('\n');
}
int nops = slang.getNumberOfUserDefinedOpNames();
for (int i = 0; i < nops; i++) {
    sb.append("userop ").append(i).append(' ')
      .append(slang.getUserDefinedOpName(i)).append('\n');
}

java.io.PrintWriter w = new java.io.PrintWriter(output, "UTF-8");
w.print(sb.toString());
w.close();

println("VENTRIS capsule function=" + pick.getName() + " entry=" + Long.toHexString(entry)
        + " len=" + len + " registers=" + regs.size() + " userops=" + nops);
println("VENTRIS done");
