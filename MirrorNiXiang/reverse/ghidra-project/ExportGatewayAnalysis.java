import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class ExportGatewayAnalysis extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String outParam = getScriptArgs().length > 0 ? getScriptArgs()[0] : "gateway-analysis.txt";
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
            "chatgpt_mirror_gateway::proxy::proxy_request",
            "chatgpt_mirror_gateway::proxy::proxy_gateway",
            "chatgpt_mirror_gateway::proxy::proxy_django",
            "chatgpt_mirror_gateway::proxy::proxy_admin",
            "chatgpt_mirror_gateway::proxy::proxy_chatgpt_api",
            "chatgpt_mirror_gateway::proxy::proxy_chatgpt_ws",
            "chatgpt_mirror_gateway::proxy::get_cfbypass_payload_with_proxy_server",
            "chatgpt_mirror_gateway::proxy::get_cached_cfbypass_payload_with_proxy_server",
            "chatgpt_mirror_gateway::proxy::clear_cfbypass_cache_entry_with_proxy_server",
            "chatgpt_mirror_gateway::proxy::apply_chrome_146_network_identity",
            "chatgpt_mirror_gateway::proxy::record_chat_requirements_pow_if_present",
            "chatgpt_mirror_gateway::db::",
            "chatgpt_mirror_gateway::moderation::review_text",
            "chatgpt_mirror_gateway::main",
            "chatgpt_mirror_gateway::run",
            "chatgpt_mirror_gateway::router"
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
            out.println("Ghidra export");
            out.println("Program=" + currentProgram.getName());
            out.println("ImageBase=0x" + currentProgram.getImageBase());
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
                    DecompileResults result = decomp.decompileFunction(f, 180, monitor);
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
                for (Reference ref : getReferencesFrom(f.getEntryPoint())) {
                    Symbol s = currentProgram.getSymbolTable().getPrimarySymbol(ref.getToAddress());
                    out.println(ref.getReferenceType() + " -> " + ref.getToAddress() + " " + (s == null ? "" : s.getName(true)));
                }
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
        println("Exported selected functions to " + outFile.getAbsolutePath());
    }
}
