ghidra.app.decompiler.DecompInterface d = new ghidra.app.decompiler.DecompInterface();
// decompileFunction dereferences this.options unconditionally; DecompInterface
// leaves it null until setOptions is called.
d.setOptions(new ghidra.app.decompiler.DecompileOptions());
d.toggleCCode(true);
d.toggleSyntaxTree(true);
d.setSimplificationStyle("decompile");
d.enableDebug(new java.io.File(
    System.getProperty("java.io.tmpdir"), "ventris/decomp_debug.xml"));
if (!d.openProgram(currentProgram)) {
    println("VENTRIS open failed: " + d.getLastMessage());
    return;
}
ghidra.program.model.listing.Function pick = null;
ghidra.program.model.listing.FunctionIterator it =
    currentProgram.getFunctionManager().getFunctions(true);
while (it.hasNext()) {
    ghidra.program.model.listing.Function g = it.next();
    long n = g.getBody().getNumAddresses();
    if (!g.isThunk() && !g.isExternal() && n > 24 && n < 160) {
        pick = g;
        break;
    }
}
if (pick == null) {
    println("VENTRIS no candidate function");
    return;
}
println("VENTRIS function=" + pick.getName() + " entry=" + pick.getEntryPoint()
        + " bytes=" + pick.getBody().getNumAddresses());
ghidra.app.decompiler.DecompileResults r = d.decompileFunction(pick, 120, monitor);
println("VENTRIS completed=" + r.decompileCompleted() + " msg=" + r.getErrorMessage());
if (r.getDecompiledFunction() != null) {
    println("VENTRIS C-BEGIN");
    println(r.getDecompiledFunction().getC());
    println("VENTRIS C-END");
}
d.dispose();
println("VENTRIS done");
