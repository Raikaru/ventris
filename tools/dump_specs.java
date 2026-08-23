// Emit the four specification strings that DecompileProcess.registerProgram sends.
// Call sequence mirrors DecompInterface.initializeProcess exactly (verified by javap).
ghidra.app.plugin.processors.sleigh.SleighLanguage slang =
        (ghidra.app.plugin.processors.sleigh.SleighLanguage) currentProgram.getLanguage();

long uniqueBase = ghidra.app.plugin.processors.sleigh.UniqueLayout.SLEIGH_BASE.getOffset(slang);

ghidra.program.model.pcode.XmlEncode enc = new ghidra.program.model.pcode.XmlEncode(false);
slang.encodeTranslator(enc, currentProgram.getAddressFactory(), uniqueBase);
String tspec = enc.toString();

enc.clear();
ghidra.program.model.pcode.PcodeDataTypeManager dtm =
        new ghidra.program.model.pcode.PcodeDataTypeManager(currentProgram, null);
dtm.encodeCoreTypes(enc);
String coretypes = enc.toString();

enc.clear();
currentProgram.getCompilerSpec().encode(enc);
String cspec = enc.toString();

generic.jar.ResourceFile pf =
        ((ghidra.program.model.lang.SleighLanguageDescription) slang.getLanguageDescription())
                .getSpecFile();
StringBuilder sb = new StringBuilder();
java.io.BufferedReader rd = new java.io.BufferedReader(
        new java.io.InputStreamReader(pf.getInputStream()));
String ln;
while ((ln = rd.readLine()) != null) {
    sb.append(ln).append('\n');
}
rd.close();
String pspec = sb.toString();

java.io.File dir = new java.io.File(
        System.getProperty("java.io.tmpdir"), "ventris/specs");
String[][ ] out = {
    { "pspec.xml", pspec }, { "cspec.xml", cspec },
    { "tspec.xml", tspec }, { "coretypes.xml", coretypes },
};
for (int i = 0; i < out.length; i++) {
    java.io.PrintWriter w = new java.io.PrintWriter(
            new java.io.File(dir, out[i][0]), "UTF-8");
    w.print(out[i][1]);
    w.close();
    println("VENTRIS wrote " + out[i][0] + " " + out[i][1].length() + " chars");
}
println("VENTRIS language=" + slang.getLanguageID() + " uniqueBase=" + uniqueBase);
println("VENTRIS done");
