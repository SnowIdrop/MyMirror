import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class DumpAuthFns extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String outParam = getScriptArgs().length > 0 ? getScriptArgs()[0] : "auth-fns.txt";
        File outFile = new File(outParam);
        outFile.getAbsoluteFile().getParentFile().mkdirs();

        DecompInterface decomp = new DecompInterface();
        DecompileOptions opts = new DecompileOptions();
        decomp.setOptions(opts);
        decomp.toggleCCode(true);
        decomp.toggleSyntaxTree(true);
        decomp.setSimplificationStyle("decompile");
        if (!decomp.openProgram(currentProgram)) {
            throw new RuntimeException("Decompiler failed to open program: " + decomp.getLastMessage());
        }

        List<String> needles = Arrays.asList(
            "chatgpt_mirror_gateway::api::",
            "chatgpt_mirror_gateway::config::",
            "chatgpt_mirror_gateway::build_router",
            "chatgpt_mirror_gateway::has_gateway_admin_secret",
            "chatgpt_mirror_gateway::insert_header_if_absent",
            "chatgpt_mirror_gateway::apply_private_no_store_headers",
            "chatgpt_mirror_gateway::init_tracing"
        );

        Map<String, Function> selected = new LinkedHashMap<>();
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            String name = f.getName(true);
            for (String needle : needles) {
                if (name.contains(needle)) {
                    selected.put(name, f);
                    break;
                }
            }
        }

        try (PrintWriter out = new PrintWriter(new OutputStreamWriter(new FileOutputStream(outFile), StandardCharsets.UTF_8))) {
            out.println("Ghidra export (auth/router focus)");
            out.println("Program=" + currentProgram.getName());
            out.println("SelectedFunctions=" + selected.size());
            out.println();

            for (Map.Entry<String, Function> e : selected.entrySet()) {
                Function f = e.getValue();
                out.println("================================================================================");
                out.println("FUNCTION " + f.getName(true));
                out.println("ENTRY 0x" + f.getEntryPoint());
                out.println("BODY " + f.getBody());
                out.println();
                try {
                    DecompileResults result = decomp.decompileFunction(f, 240, monitor);
                    if (result != null && result.decompileCompleted()) {
                        out.println(result.getDecompiledFunction().getC());
                    } else {
                        out.println("// DECOMPILATION_FAILED: " + (result == null ? "null result" : result.getErrorMessage()));
                    }
                } catch (Exception ex) {
                    out.println("// DECOMPILATION_EXCEPTION: " + ex);
                }
                out.println();
                out.println("-- CALLS --");
                Set<String> called = new TreeSet<>();
                for (Address a : f.getBody().getAddresses(true)) {
                    for (Reference ref : getReferencesFrom(a)) {
                        if (!ref.getReferenceType().isCall()) continue;
                        Function callee = currentProgram.getFunctionManager().getFunctionAt(ref.getToAddress());
                        called.add(callee == null ? ref.getToAddress().toString() : callee.getName(true));
                    }
                }
                for (String c : called) out.println("callee " + c);
                out.println();
            }
        } finally {
            decomp.dispose();
        }
        println("Dumped auth/router functions to " + outFile.getAbsolutePath());
    }
}
