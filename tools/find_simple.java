ghidra.program.model.listing.FunctionIterator fit =
        currentProgram.getFunctionManager().getFunctions(true);
int found = 0;
while (fit.hasNext() && found < 40) {
    ghidra.program.model.listing.Function g = fit.next();
    long n = g.getBody().getNumAddresses();
    if (g.isThunk() || g.isExternal() || n < 1 || n > 96) continue;
    ghidra.program.model.listing.InstructionIterator ii =
        currentProgram.getListing().getInstructions(g.getBody(), true);
    String last = "";
    boolean calls = false;
    int ins = 0, ops = 0;
    while (ii.hasNext()) {
        ghidra.program.model.listing.Instruction x = ii.next();
        last = x.getMnemonicString();
        ins++;
        for (ghidra.program.model.pcode.PcodeOp o : x.getPcode()) {
            ops++;
            int c = o.getOpcode();
            if (c == ghidra.program.model.pcode.PcodeOp.CALL
                    || c == ghidra.program.model.pcode.PcodeOp.CALLIND
                    || c == ghidra.program.model.pcode.PcodeOp.BRANCHIND) calls = true;
        }
    }
    if (last.startsWith("RET") && !calls) {
        println(g.getName() + " " + g.getEntryPoint() + " bytes=" + n
                + " ins=" + ins + " ops=" + ops + " last=" + last);
        found++;
    }
}
