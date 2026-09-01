/* ###
 * Ventris service: a tiny JSON-RPC stdio bridge to Ghidra's Java APIs.
 *
 * Stage 1 architecture: the Rust core owns the program database and the
 * client-facing Core API; this process exists only so the core can reach
 * Ghidra's loaders, analyzers, and decompiler without a JVM embedded in the
 * final product. Everything this file touches was verified against the
 * extracted Ghidra 12.1.3 sources in .ghidra-java/ rather than recalled from
 * documentation.
 */
package net.ventris;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;

/**
 * Framing: one JSON document per line on stdin, one JSON document per line on
 * stdout. Every response carries either "result" or "error"; ids are echoed
 * verbatim. Diagnostics never touch stdout - the launcher points Ghidra's own
 * logging machinery elsewhere, and unexpected stack traces go to stderr.
 */
public final class Main {
    private static final Gson GSON = new GsonBuilder().disableHtmlEscaping().create();

    public static void main(String[] args) {
        ServiceOptions options;
        try {
            options = ServiceOptions.fromArgs(args);
        } catch (IllegalArgumentException e) {
            System.err.println("ventris-service: " + e.getMessage());
            System.err.println("usage: ventris-service --install-dir DIR [--project-dir DIR]");
            System.exit(2);
            return;
        }
        Dispatcher dispatcher;
        try {
            dispatcher = new Dispatcher(options);
        } catch (IOException | ghidra.util.exception.NotFoundException
                | ghidra.util.NotOwnerException | ghidra.framework.store.LockException e) {
            System.err.println("ventris-service: failed to initialize Ghidra: " + e.getMessage());
            System.exit(3);
            return;
        }

        PrintStream out = new PrintStream(System.out, true, StandardCharsets.UTF_8);
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        try {
            String line;
            while ((line = in.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty()) {
                    continue;
                }
                String response = handle(line, dispatcher);
                if (response != null) {
                    out.println(response);
                }
            }
        } catch (IOException e) {
            System.err.println("ventris-service: stdin closed: " + e.getMessage());
        } finally {
            dispatcher.shutdown();
        }
        System.exit(0);
    }

    /**
     * Handles one request document, returning the response document or null
     * when the request was a notification (no id) that must not be answered.
     */
    private static String handle(String line, Dispatcher dispatcher) {
        JsonElement parsed;
        try {
            parsed = JsonParser.parseString(line);
        } catch (JsonSyntaxException e) {
            return GSON.toJson(error(null, -32700, "parse error: " + e.getMessage()));
        }
        if (!parsed.isJsonObject()) {
            return GSON.toJson(error(null, -32600, "request must be a JSON object"));
        }
        JsonObject request = parsed.getAsJsonObject();
        JsonElement id = request.get("id");
        if (id == null) {
            // Notifications still run; they just produce no output.
            try {
                dispatcher.dispatch(request, null);
            } catch (RuntimeException e) {
                System.err.println("ventris-service: notification failed: " + e);
            }
            return null;
        }
        try {
            JsonElement result = dispatcher.dispatch(request, id);
            JsonObject ok = new JsonObject();
            ok.add("id", id);
            ok.add("result", result);
            return GSON.toJson(ok);
        } catch (RpcError e) {
            return GSON.toJson(error(id, e.code, e.getMessage()));
        } catch (RuntimeException e) {
            return GSON.toJson(error(id, -32000, e.toString()));
        }
    }

    private static JsonObject error(JsonElement id, int code, String message) {
        JsonObject err = new JsonObject();
        err.addProperty("code", code);
        err.addProperty("message", message);
        JsonObject doc = new JsonObject();
        doc.add("id", id);
        doc.add("error", err);
        return doc;
    }

    /** An error already shaped for the wire. */
    static final class RpcError extends RuntimeException {
        final int code;

        RpcError(int code, String message) {
            super(message);
            this.code = code;
        }
    }
}
