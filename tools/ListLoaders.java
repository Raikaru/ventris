import ghidra.app.script.GhidraScript;
import ghidra.app.util.opinion.Loader;
import ghidra.util.classfinder.ClassSearcher;
import java.util.ArrayList;
import java.util.List;

/**
 * Prints every loader Ghidra discovered, so a missing extension can be told
 * apart from a mistyped loader name.
 *
 * <p>{@code analyzeHeadless -loader} rejects an unknown name with the same
 * message whether the extension failed to install, failed to load, or was
 * simply spelled differently. This script answers which.
 */
public class ListLoaders extends GhidraScript {
    @Override
    public void run() throws Exception {
        List<String> names = new ArrayList<>();
        for (Loader loader : ClassSearcher.getInstances(Loader.class)) {
            names.add(loader.getName() + "  [" + loader.getClass().getName() + "]");
        }
        names.sort(String::compareTo);
        println("VENTRIS loaders count=" + names.size());
        for (String name : names) {
            println("VENTRIS loader " + name);
        }
        println("VENTRIS loaders done");
    }
}
