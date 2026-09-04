// Oracle-only postScript; does not alter bridge provenance or program state.
// APIs verified in Ghidra 12.1.3 sources: Function, FunctionManager, Memory,
// MemoryBlock, GhidraScript. ElfProgramBuilder.createExternalBlock and
// evaluateElfSymbol establish the artificial EXTERNAL + external-thunk evidence.
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryBlock;
import java.nio.file.Files;
import java.nio.file.Path;

public class ExportFunctionScoring extends GhidraScript {
    @Override
    public void run() throws Exception {
        JsonArray rows = new JsonArray();
        for (Function function : currentProgram.getFunctionManager().getFunctions(true)) {
            if (function.isExternal()) continue;
            JsonObject row = new JsonObject();
            row.addProperty("entry", function.getEntryPoint().toString());
            row.addProperty("name", function.getName());
            MemoryBlock block = currentProgram.getMemory().getBlock(function.getEntryPoint());
            if (block != null) {
                row.addProperty("block_name", block.getName());
                row.addProperty("block_start", block.getStart().toString());
                row.addProperty("block_end", block.getEnd().toString());
                row.addProperty("block_artificial", block.isArtificial());
                row.addProperty("block_source", block.getSourceName());
                row.addProperty("block_execute", block.isExecute());
            }
            Function target = function.getThunkedFunction(false);
            row.addProperty("thunk_external", target != null && target.isExternal());
            if (target != null) row.addProperty("thunk_target", target.getName());
            rows.add(row);
        }
        Files.writeString(Path.of(getScriptArgs()[0]), rows.toString());
    }
}
