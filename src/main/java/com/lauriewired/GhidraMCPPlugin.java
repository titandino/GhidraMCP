package com.lauriewired;

import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.GlobalNamespace;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighFunctionDBUtil.ReturnCommitOption;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.NamespaceUtils;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.cmd.function.SetVariableNameCmd;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Undefined1DataType;
import ghidra.program.model.listing.Variable;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.decompiler.ClangToken;
import ghidra.framework.options.Options;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnionDataType;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.Union;
import ghidra.program.model.data.Composite;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import javax.swing.SwingUtilities;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = ghidra.app.DeveloperPluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "HTTP server plugin",
    description = "Starts an embedded HTTP server to expose program data. Port configurable via Tool Options."
)
public class GhidraMCPPlugin extends Plugin {

    private HttpServer server;
    private static final String OPTION_CATEGORY_NAME = "GhidraMCP HTTP Server";
    private static final String PORT_OPTION_NAME = "Server Port";
    private static final int DEFAULT_PORT = 8080;

    public GhidraMCPPlugin(PluginTool tool) {
        super(tool);
        Msg.info(this, "GhidraMCPPlugin loading...");

        // Register the configuration option
        Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        options.registerOption(PORT_OPTION_NAME, DEFAULT_PORT,
            null, // No help location for now
            "The network port number the embedded HTTP server will listen on. " +
            "Requires Ghidra restart or plugin reload to take effect after changing.");

        try {
            startServer();
        }
        catch (IOException e) {
            Msg.error(this, "Failed to start HTTP server", e);
        }
        Msg.info(this, "GhidraMCPPlugin loaded!");
    }

    private void startServer() throws IOException {
        // Read the configured port
        Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        int port = options.getInt(PORT_OPTION_NAME, DEFAULT_PORT);

        // Stop existing server if running (e.g., if plugin is reloaded)
        if (server != null) {
            Msg.info(this, "Stopping existing HTTP server before starting new one.");
            server.stop(0);
            server = null;
        }

        server = HttpServer.create(new InetSocketAddress(port), 0);

        // Each listing endpoint uses offset & limit from query params:
        server.createContext("/methods", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, getAllFunctionNames(offset, limit));
        });

        server.createContext("/classes", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, getAllClassNames(offset, limit));
        });

        server.createContext("/decompile", exchange -> {
            String name = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            sendResponse(exchange, decompileFunctionByName(name));
        });

        server.createContext("/renameFunction", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String response = renameFunction(params.get("oldName"), params.get("newName"))
                    ? "Renamed successfully" : "Rename failed";
            sendResponse(exchange, response);
        });

        server.createContext("/renameData", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            renameDataAtAddress(params.get("address"), params.get("newName"));
            sendResponse(exchange, "Rename data attempted");
        });

        server.createContext("/renameVariable", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionName = params.get("functionName");
            String oldName = params.get("oldName");
            String newName = params.get("newName");
            String result = renameVariableInFunction(functionName, oldName, newName);
            sendResponse(exchange, result);
        });

        server.createContext("/segments", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listSegments(offset, limit));
        });

        server.createContext("/imports", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listImports(offset, limit));
        });

        server.createContext("/exports", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listExports(offset, limit));
        });

        server.createContext("/namespaces", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listNamespaces(offset, limit));
        });

        server.createContext("/data", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listDefinedData(offset, limit));
        });

        server.createContext("/searchFunctions", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String searchTerm = qparams.get("query");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, searchFunctionsByName(searchTerm, offset, limit));
        });

        // New API endpoints based on requirements
        
        server.createContext("/get_function_by_address", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, getFunctionByAddress(address));
        });

        server.createContext("/get_current_address", exchange -> {
            sendResponse(exchange, getCurrentAddress());
        });

        server.createContext("/get_current_function", exchange -> {
            sendResponse(exchange, getCurrentFunction());
        });

        server.createContext("/list_functions", exchange -> {
            sendResponse(exchange, listFunctions());
        });

        server.createContext("/decompile_function", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, decompileFunctionByAddress(address));
        });

        server.createContext("/disassemble_function", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, disassembleFunction(address));
        });

        server.createContext("/set_decompiler_comment", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String comment = params.get("comment");
            boolean success = setDecompilerComment(address, comment);
            sendResponse(exchange, success ? "Comment set successfully" : "Failed to set comment");
        });

        server.createContext("/set_disassembly_comment", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String comment = params.get("comment");
            boolean success = setDisassemblyComment(address, comment);
            sendResponse(exchange, success ? "Comment set successfully" : "Failed to set comment");
        });

        server.createContext("/rename_function_by_address", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String newName = params.get("new_name");
            boolean success = renameFunctionByAddress(functionAddress, newName);
            sendResponse(exchange, success ? "Function renamed successfully" : "Failed to rename function");
        });

        server.createContext("/set_function_prototype", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String prototype = params.get("prototype");

            // Call the set prototype function and get detailed result
            PrototypeResult result = setFunctionPrototype(functionAddress, prototype);

            if (result.isSuccess()) {
                // Even with successful operations, include any warning messages for debugging
                String successMsg = "Function prototype set successfully";
                if (!result.getErrorMessage().isEmpty()) {
                    successMsg += "\n\nWarnings/Debug Info:\n" + result.getErrorMessage();
                }
                sendResponse(exchange, successMsg);
            } else {
                // Return the detailed error message to the client
                sendResponse(exchange, "Failed to set function prototype: " + result.getErrorMessage());
            }
        });

        server.createContext("/set_local_variable_type", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String variableName = params.get("variable_name");
            String newType = params.get("new_type");

            // Capture detailed information about setting the type
            StringBuilder responseMsg = new StringBuilder();
            responseMsg.append("Setting variable type: ").append(variableName)
                      .append(" to ").append(newType)
                      .append(" in function at ").append(functionAddress).append("\n\n");

            // Attempt to find the data type in various categories
            Program program = getCurrentProgram();
            if (program != null) {
                DataTypeManager dtm = program.getDataTypeManager();
                DataType directType = findDataTypeByNameInAllCategories(dtm, newType);
                if (directType != null) {
                    responseMsg.append("Found type: ").append(directType.getPathName()).append("\n");
                } else if (newType.startsWith("P") && newType.length() > 1) {
                    String baseTypeName = newType.substring(1);
                    DataType baseType = findDataTypeByNameInAllCategories(dtm, baseTypeName);
                    if (baseType != null) {
                        responseMsg.append("Found base type for pointer: ").append(baseType.getPathName()).append("\n");
                    } else {
                        responseMsg.append("Base type not found for pointer: ").append(baseTypeName).append("\n");
                    }
                } else {
                    responseMsg.append("Type not found directly: ").append(newType).append("\n");
                }
            }

            // Try to set the type
            boolean success = setLocalVariableType(functionAddress, variableName, newType);

            String successMsg = success ? "Variable type set successfully" : "Failed to set variable type";
            responseMsg.append("\nResult: ").append(successMsg);

            sendResponse(exchange, responseMsg.toString());
        });

        server.createContext("/xrefs_to", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getXrefsTo(address, offset, limit));
        });

        server.createContext("/xrefs_from", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getXrefsFrom(address, offset, limit));
        });

        server.createContext("/function_xrefs", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String name = qparams.get("name");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getFunctionXrefs(name, offset, limit));
        });

        server.createContext("/strings", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            String filter = qparams.get("filter");
            sendResponse(exchange, listDefinedStrings(offset, limit, filter));
        });

        server.createContext("/createNamespace", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String namespacePath = params.get("namespace_path");
            sendResponse(exchange, createNamespace(namespacePath));
        });

        server.createContext("/moveSymbolToNamespace", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String namespacePath = params.get("namespace_path");
            sendResponse(exchange, moveSymbolToNamespace(address, namespacePath));
        });

        server.createContext("/listNamespaceContents", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String namespacePath = qparams.get("namespace_path");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, listNamespaceContents(namespacePath, offset, limit));
        });

        // Data structure management endpoints
        server.createContext("/createStruct", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String name = params.get("name");
            int size = parseIntOrDefault(params.get("size"), 0);
            String categoryPath = params.get("category_path");
            sendResponse(exchange, createStruct(name, size, categoryPath));
        });

        server.createContext("/addStructField", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String structName = params.get("struct_name");
            int fieldOffset = parseIntOrDefault(params.get("offset"), -1);
            String fieldType = params.get("field_type");
            String fieldName = params.get("field_name");
            int fieldLength = parseIntOrDefault(params.get("field_length"), 0);
            String comment = params.get("comment");
            sendResponse(exchange, addStructField(structName, fieldOffset, fieldType, fieldName, fieldLength, comment));
        });

        server.createContext("/deleteStructField", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String structName = params.get("struct_name");
            int fieldOffset = parseIntOrDefault(params.get("offset"), -1);
            sendResponse(exchange, deleteStructField(structName, fieldOffset));
        });

        server.createContext("/getStructFields", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String structName = qparams.get("struct_name");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getStructFields(structName, offset, limit));
        });

        server.createContext("/createUnion", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String name = params.get("name");
            String categoryPath = params.get("category_path");
            sendResponse(exchange, createUnion(name, categoryPath));
        });

        server.createContext("/addUnionField", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String unionName = params.get("union_name");
            String fieldType = params.get("field_type");
            String fieldName = params.get("field_name");
            int fieldLength = parseIntOrDefault(params.get("field_length"), 0);
            String comment = params.get("comment");
            sendResponse(exchange, addUnionField(unionName, fieldType, fieldName, fieldLength, comment));
        });

        server.createContext("/createEnum", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String name = params.get("name");
            int size = parseIntOrDefault(params.get("size"), 4);
            String categoryPath = params.get("category_path");
            sendResponse(exchange, createEnum(name, size, categoryPath));
        });

        server.createContext("/addEnumValue", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String enumName = params.get("enum_name");
            String entryName = params.get("entry_name");
            long value = parseLongOrDefault(params.get("value"), 0);
            sendResponse(exchange, addEnumValue(enumName, entryName, value));
        });

        server.createContext("/getDataType", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String name = qparams.get("name");
            sendResponse(exchange, getDataTypeInfo(name));
        });

        server.createContext("/applyStructToAddress", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String structName = params.get("struct_name");
            sendResponse(exchange, applyStructToAddress(address, structName));
        });

        // Function signature refactoring endpoints
        server.createContext("/getFunctionSignature", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, getFunctionSignatureDetails(address));
        });

        server.createContext("/setReturnType", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String returnType = params.get("return_type");
            sendResponse(exchange, setFunctionReturnType(functionAddress, returnType));
        });

        server.createContext("/addParameter", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String paramName = params.get("param_name");
            String paramType = params.get("param_type");
            int index = parseIntOrDefault(params.get("index"), -1);
            sendResponse(exchange, addFunctionParameter(functionAddress, paramName, paramType, index));
        });

        server.createContext("/removeParameter", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            int index = parseIntOrDefault(params.get("index"), -1);
            sendResponse(exchange, removeFunctionParameter(functionAddress, index));
        });

        server.createContext("/changeParameterType", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            int index = parseIntOrDefault(params.get("index"), -1);
            String newType = params.get("new_type");
            sendResponse(exchange, changeFunctionParameterType(functionAddress, index, newType));
        });

        server.createContext("/renameParameter", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            int index = parseIntOrDefault(params.get("index"), -1);
            String newName = params.get("new_name");
            sendResponse(exchange, renameFunctionParameter(functionAddress, index, newName));
        });

        server.createContext("/setCallingConvention", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String convention = params.get("calling_convention");
            sendResponse(exchange, setFunctionCallingConvention(functionAddress, convention));
        });

        server.setExecutor(null);
        new Thread(() -> {
            try {
                server.start();
                Msg.info(this, "GhidraMCP HTTP server started on port " + port);
            } catch (Exception e) {
                Msg.error(this, "Failed to start HTTP server on port " + port + ". Port might be in use.", e);
                server = null; // Ensure server isn't considered running
            }
        }, "GhidraMCP-HTTP-Server").start();
    }

    // ----------------------------------------------------------------------------------
    // Pagination-aware listing methods
    // ----------------------------------------------------------------------------------

    private String getAllFunctionNames(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> names = new ArrayList<>();
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            names.add(getFullyQualifiedFunctionName(f));
        }
        return paginateList(names, offset, limit);
    }

    private String getAllClassNames(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Set<String> classNames = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !ns.isGlobal()) {
                classNames.add(ns.getName(true));
            }
        }
        // Convert set to list for pagination
        List<String> sorted = new ArrayList<>(classNames);
        Collections.sort(sorted);
        return paginateList(sorted, offset, limit);
    }

    private String listSegments(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            lines.add(String.format("%s: %s - %s", block.getName(), block.getStart(), block.getEnd()));
        }
        return paginateList(lines, offset, limit);
    }

    private String listImports(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (Symbol symbol : program.getSymbolTable().getExternalSymbols()) {
            lines.add(symbol.getName() + " -> " + symbol.getAddress());
        }
        return paginateList(lines, offset, limit);
    }

    private String listExports(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        SymbolTable table = program.getSymbolTable();
        SymbolIterator it = table.getAllSymbols(true);

        List<String> lines = new ArrayList<>();
        while (it.hasNext()) {
            Symbol s = it.next();
            // On older Ghidra, "export" is recognized via isExternalEntryPoint()
            if (s.isExternalEntryPoint()) {
                lines.add(s.getName() + " -> " + s.getAddress());
            }
        }
        return paginateList(lines, offset, limit);
    }

    private String listNamespaces(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Set<String> namespaces = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            while (ns != null && !(ns instanceof GlobalNamespace)) {
                namespaces.add(ns.getName(true));
                ns = ns.getParentNamespace();
            }
        }
        List<String> sorted = new ArrayList<>(namespaces);
        Collections.sort(sorted);
        return paginateList(sorted, offset, limit);
    }

    private String listDefinedData(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            DataIterator it = program.getListing().getDefinedData(block.getStart(), true);
            while (it.hasNext()) {
                Data data = it.next();
                if (block.contains(data.getAddress())) {
                    String label   = data.getLabel() != null ? data.getLabel() : "(unnamed)";
                    String valRepr = data.getDefaultValueRepresentation();
                    lines.add(String.format("%s: %s = %s",
                        data.getAddress(),
                        escapeNonAscii(label),
                        escapeNonAscii(valRepr)
                    ));
                }
            }
        }
        return paginateList(lines, offset, limit);
    }

    private String searchFunctionsByName(String searchTerm, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (searchTerm == null || searchTerm.isEmpty()) return "Search term is required";

        List<String> matches = new ArrayList<>();
        String lowerSearch = searchTerm.toLowerCase();
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            String simpleName = func.getName();
            String qualifiedName = getFullyQualifiedFunctionName(func);
            if (simpleName.toLowerCase().contains(lowerSearch) ||
                qualifiedName.toLowerCase().contains(lowerSearch)) {
                matches.add(String.format("%s @ %s", qualifiedName, func.getEntryPoint()));
            }
        }

        Collections.sort(matches);

        if (matches.isEmpty()) {
            return "No functions matching '" + searchTerm + "'";
        }
        return paginateList(matches, offset, limit);
    }

    // ----------------------------------------------------------------------------------
    // Logic for rename, decompile, etc.
    // ----------------------------------------------------------------------------------

    private String decompileFunctionByName(String name) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        Function func = findFunctionByName(program, name);
        if (func == null) return "Function not found";
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);
        DecompileResults result =
            decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
        if (result != null && result.decompileCompleted()) {
            return result.getDecompiledFunction().getC();
        }
        return "Decompilation failed";
    }

    private boolean renameFunction(String oldName, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return false;

        AtomicBoolean successFlag = new AtomicBoolean(false);
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename function via HTTP");
                try {
                    Function func = findFunctionByName(program, oldName);
                    if (func != null) {
                        NamespacedName nn = resolveNamespacedName(program, newName);
                        if (nn != null) {
                            func.getSymbol().setNameAndNamespace(nn.simpleName, nn.namespace, SourceType.USER_DEFINED);
                        } else {
                            func.setName(newName, SourceType.USER_DEFINED);
                        }
                        successFlag.set(true);
                    }
                }
                catch (Exception e) {
                    Msg.error(this, "Error renaming function", e);
                }
                finally {
                    successFlag.set(program.endTransaction(tx, successFlag.get()));
                }
            });
        }
        catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename on Swing thread", e);
        }
        return successFlag.get();
    }

    private void renameDataAtAddress(String addressStr, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return;

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename data");
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    Listing listing = program.getListing();
                    Data data = listing.getDefinedDataAt(addr);
                    if (data != null) {
                        SymbolTable symTable = program.getSymbolTable();
                        Symbol symbol = symTable.getPrimarySymbol(addr);
                        NamespacedName nn = resolveNamespacedName(program, newName);
                        if (symbol != null) {
                            if (nn != null) {
                                symbol.setNameAndNamespace(nn.simpleName, nn.namespace, SourceType.USER_DEFINED);
                            } else {
                                symbol.setName(newName, SourceType.USER_DEFINED);
                            }
                        } else {
                            if (nn != null) {
                                symTable.createLabel(addr, nn.simpleName, nn.namespace, SourceType.USER_DEFINED);
                            } else {
                                symTable.createLabel(addr, newName, SourceType.USER_DEFINED);
                            }
                        }
                    }
                }
                catch (Exception e) {
                    Msg.error(this, "Rename data error", e);
                }
                finally {
                    program.endTransaction(tx, true);
                }
            });
        }
        catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename data on Swing thread", e);
        }
    }

    private String renameVariableInFunction(String functionName, String oldVarName, String newVarName) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);

        Function func = findFunctionByName(program, functionName);
        if (func == null) {
            return "Function not found";
        }

        DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
        if (result == null || !result.decompileCompleted()) {
            return "Decompilation failed";
        }

        HighFunction highFunction = result.getHighFunction();
        if (highFunction == null) {
            return "Decompilation failed (no high function)";
        }

        LocalSymbolMap localSymbolMap = highFunction.getLocalSymbolMap();
        if (localSymbolMap == null) {
            return "Decompilation failed (no local symbol map)";
        }

        HighSymbol highSymbol = null;
        Iterator<HighSymbol> symbols = localSymbolMap.getSymbols();
        while (symbols.hasNext()) {
            HighSymbol symbol = symbols.next();
            String symbolName = symbol.getName();
            
            if (symbolName.equals(oldVarName)) {
                highSymbol = symbol;
            }
            if (symbolName.equals(newVarName)) {
                return "Error: A variable with name '" + newVarName + "' already exists in this function";
            }
        }

        if (highSymbol == null) {
            return "Variable not found";
        }

        boolean commitRequired = checkFullCommit(highSymbol, highFunction);

        final HighSymbol finalHighSymbol = highSymbol;
        final Function finalFunction = func;
        AtomicBoolean successFlag = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {           
                int tx = program.startTransaction("Rename variable");
                try {
                    if (commitRequired) {
                        HighFunctionDBUtil.commitParamsToDatabase(highFunction, false,
                            ReturnCommitOption.NO_COMMIT, finalFunction.getSignatureSource());
                    }
                    HighFunctionDBUtil.updateDBVariable(
                        finalHighSymbol,
                        newVarName,
                        null,
                        SourceType.USER_DEFINED
                    );
                    successFlag.set(true);
                }
                catch (Exception e) {
                    Msg.error(this, "Failed to rename variable", e);
                }
                finally {
                    successFlag.set(program.endTransaction(tx, true));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            String errorMsg = "Failed to execute rename on Swing thread: " + e.getMessage();
            Msg.error(this, errorMsg, e);
            return errorMsg;
        }
        return successFlag.get() ? "Variable renamed" : "Failed to rename variable";
    }

    /**
     * Copied from AbstractDecompilerAction.checkFullCommit, it's protected.
	 * Compare the given HighFunction's idea of the prototype with the Function's idea.
	 * Return true if there is a difference. If a specific symbol is being changed,
	 * it can be passed in to check whether or not the prototype is being affected.
	 * @param highSymbol (if not null) is the symbol being modified
	 * @param hfunction is the given HighFunction
	 * @return true if there is a difference (and a full commit is required)
	 */
	protected static boolean checkFullCommit(HighSymbol highSymbol, HighFunction hfunction) {
		if (highSymbol != null && !highSymbol.isParameter()) {
			return false;
		}
		Function function = hfunction.getFunction();
		Parameter[] parameters = function.getParameters();
		LocalSymbolMap localSymbolMap = hfunction.getLocalSymbolMap();
		int numParams = localSymbolMap.getNumParams();
		if (numParams != parameters.length) {
			return true;
		}

		for (int i = 0; i < numParams; i++) {
			HighSymbol param = localSymbolMap.getParamSymbol(i);
			if (param.getCategoryIndex() != i) {
				return true;
			}
			VariableStorage storage = param.getStorage();
			// Don't compare using the equals method so that DynamicVariableStorage can match
			if (0 != storage.compareTo(parameters[i].getVariableStorage())) {
				return true;
			}
		}

		return false;
	}

    // ----------------------------------------------------------------------------------
    // New methods to implement the new functionalities
    // ----------------------------------------------------------------------------------

    /**
     * Get function by address
     */
    private String getFunctionByAddress(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = program.getFunctionManager().getFunctionAt(addr);

            if (func == null) return "No function found at address " + addressStr;

            return String.format("Function: %s at %s\nSignature: %s\nEntry: %s\nBody: %s - %s",
                func.getName(),
                func.getEntryPoint(),
                func.getSignature(),
                func.getEntryPoint(),
                func.getBody().getMinAddress(),
                func.getBody().getMaxAddress());
        } catch (Exception e) {
            return "Error getting function: " + e.getMessage();
        }
    }

    /**
     * Get current address selected in Ghidra GUI
     */
    private String getCurrentAddress() {
        CodeViewerService service = tool.getService(CodeViewerService.class);
        if (service == null) return "Code viewer service not available";

        ProgramLocation location = service.getCurrentLocation();
        return (location != null) ? location.getAddress().toString() : "No current location";
    }

    /**
     * Get current function selected in Ghidra GUI
     */
    private String getCurrentFunction() {
        CodeViewerService service = tool.getService(CodeViewerService.class);
        if (service == null) return "Code viewer service not available";

        ProgramLocation location = service.getCurrentLocation();
        if (location == null) return "No current location";

        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Function func = program.getFunctionManager().getFunctionContaining(location.getAddress());
        if (func == null) return "No function at current location: " + location.getAddress();

        return String.format("Function: %s at %s\nSignature: %s",
            func.getName(),
            func.getEntryPoint(),
            func.getSignature());
    }

    /**
     * List all functions in the database
     */
    private String listFunctions() {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        StringBuilder result = new StringBuilder();
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            result.append(String.format("%s at %s\n",
                getFullyQualifiedFunctionName(func),
                func.getEntryPoint()));
        }

        return result.toString();
    }

    /**
     * Gets a function at the given address or containing the address
     * @return the function or null if not found
     */
    private Function getFunctionForAddress(Program program, Address addr) {
        Function func = program.getFunctionManager().getFunctionAt(addr);
        if (func == null) {
            func = program.getFunctionManager().getFunctionContaining(addr);
        }
        return func;
    }

    /**
     * Decompile a function at the given address
     */
    private String decompileFunctionByAddress(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = getFunctionForAddress(program, addr);
            if (func == null) return "No function found at or containing address " + addressStr;

            DecompInterface decomp = new DecompInterface();
            decomp.openProgram(program);
            DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());

            return (result != null && result.decompileCompleted()) 
                ? result.getDecompiledFunction().getC() 
                : "Decompilation failed";
        } catch (Exception e) {
            return "Error decompiling function: " + e.getMessage();
        }
    }

    /**
     * Get assembly code for a function
     */
    private String disassembleFunction(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = getFunctionForAddress(program, addr);
            if (func == null) return "No function found at or containing address " + addressStr;

            StringBuilder result = new StringBuilder();
            Listing listing = program.getListing();
            Address start = func.getEntryPoint();
            Address end = func.getBody().getMaxAddress();

            InstructionIterator instructions = listing.getInstructions(start, true);
            while (instructions.hasNext()) {
                Instruction instr = instructions.next();
                if (instr.getAddress().compareTo(end) > 0) {
                    break; // Stop if we've gone past the end of the function
                }
                String comment = listing.getComment(CodeUnit.EOL_COMMENT, instr.getAddress());
                comment = (comment != null) ? "; " + comment : "";

                result.append(String.format("%s: %s %s\n", 
                    instr.getAddress(), 
                    instr.toString(),
                    comment));
            }

            return result.toString();
        } catch (Exception e) {
            return "Error disassembling function: " + e.getMessage();
        }
    }    

    /**
     * Set a comment using the specified comment type (PRE_COMMENT or EOL_COMMENT)
     */
    private boolean setCommentAtAddress(String addressStr, String comment, int commentType, String transactionName) {
        Program program = getCurrentProgram();
        if (program == null) return false;
        if (addressStr == null || addressStr.isEmpty() || comment == null) return false;

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction(transactionName);
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    program.getListing().setComment(addr, commentType, comment);
                    success.set(true);
                } catch (Exception e) {
                    Msg.error(this, "Error setting " + transactionName.toLowerCase(), e);
                } finally {
                    success.set(program.endTransaction(tx, success.get()));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute " + transactionName.toLowerCase() + " on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Set a comment for a given address in the function pseudocode
     */
    private boolean setDecompilerComment(String addressStr, String comment) {
        return setCommentAtAddress(addressStr, comment, CodeUnit.PRE_COMMENT, "Set decompiler comment");
    }

    /**
     * Set a comment for a given address in the function disassembly
     */
    private boolean setDisassemblyComment(String addressStr, String comment) {
        return setCommentAtAddress(addressStr, comment, CodeUnit.EOL_COMMENT, "Set disassembly comment");
    }

    /**
     * Class to hold the result of a prototype setting operation
     */
    private static class PrototypeResult {
        private final boolean success;
        private final String errorMessage;

        public PrototypeResult(boolean success, String errorMessage) {
            this.success = success;
            this.errorMessage = errorMessage;
        }

        public boolean isSuccess() {
            return success;
        }

        public String getErrorMessage() {
            return errorMessage;
        }
    }

    /**
     * Rename a function by its address
     */
    private boolean renameFunctionByAddress(String functionAddrStr, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return false;
        if (functionAddrStr == null || functionAddrStr.isEmpty() || 
            newName == null || newName.isEmpty()) {
            return false;
        }

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                performFunctionRename(program, functionAddrStr, newName, success);
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename function on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Helper method to perform the actual function rename within a transaction
     */
    private void performFunctionRename(Program program, String functionAddrStr, String newName, AtomicBoolean success) {
        int tx = program.startTransaction("Rename function by address");
        try {
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);

            if (func == null) {
                Msg.error(this, "Could not find function at address: " + functionAddrStr);
                return;
            }

            NamespacedName nn = resolveNamespacedName(program, newName);
            if (nn != null) {
                func.getSymbol().setNameAndNamespace(nn.simpleName, nn.namespace, SourceType.USER_DEFINED);
            } else {
                func.setName(newName, SourceType.USER_DEFINED);
            }
            success.set(true);
        } catch (Exception e) {
            Msg.error(this, "Error renaming function by address", e);
        } finally {
            program.endTransaction(tx, success.get());
        }
    }

    /**
     * Set a function's prototype with proper error handling using ApplyFunctionSignatureCmd
     */
    private PrototypeResult setFunctionPrototype(String functionAddrStr, String prototype) {
        // Input validation
        Program program = getCurrentProgram();
        if (program == null) return new PrototypeResult(false, "No program loaded");
        if (functionAddrStr == null || functionAddrStr.isEmpty()) {
            return new PrototypeResult(false, "Function address is required");
        }
        if (prototype == null || prototype.isEmpty()) {
            return new PrototypeResult(false, "Function prototype is required");
        }

        final StringBuilder errorMessage = new StringBuilder();
        final AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> 
                applyFunctionPrototype(program, functionAddrStr, prototype, success, errorMessage));
        } catch (InterruptedException | InvocationTargetException e) {
            String msg = "Failed to set function prototype on Swing thread: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        }

        return new PrototypeResult(success.get(), errorMessage.toString());
    }

    /**
     * Helper method that applies the function prototype within a transaction
     */
    private void applyFunctionPrototype(Program program, String functionAddrStr, String prototype, 
                                       AtomicBoolean success, StringBuilder errorMessage) {
        try {
            // Get the address and function
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);

            if (func == null) {
                String msg = "Could not find function at address: " + functionAddrStr;
                errorMessage.append(msg);
                Msg.error(this, msg);
                return;
            }

            Msg.info(this, "Setting prototype for function " + func.getName() + ": " + prototype);

            // Store original prototype as a comment for reference
            addPrototypeComment(program, func, prototype);

            // Use ApplyFunctionSignatureCmd to parse and apply the signature
            parseFunctionSignatureAndApply(program, addr, prototype, success, errorMessage);

        } catch (Exception e) {
            String msg = "Error setting function prototype: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        }
    }

    /**
     * Add a comment showing the prototype being set
     */
    private void addPrototypeComment(Program program, Function func, String prototype) {
        int txComment = program.startTransaction("Add prototype comment");
        try {
            program.getListing().setComment(
                func.getEntryPoint(), 
                CodeUnit.PLATE_COMMENT, 
                "Setting prototype: " + prototype
            );
        } finally {
            program.endTransaction(txComment, true);
        }
    }

    /**
     * Parse and apply the function signature with error handling
     */
    private void parseFunctionSignatureAndApply(Program program, Address addr, String prototype,
                                              AtomicBoolean success, StringBuilder errorMessage) {
        // Use ApplyFunctionSignatureCmd to parse and apply the signature
        int txProto = program.startTransaction("Set function prototype");
        try {
            // Get data type manager
            DataTypeManager dtm = program.getDataTypeManager();

            // Get data type manager service
            ghidra.app.services.DataTypeManagerService dtms = 
                tool.getService(ghidra.app.services.DataTypeManagerService.class);

            // Create function signature parser
            ghidra.app.util.parser.FunctionSignatureParser parser = 
                new ghidra.app.util.parser.FunctionSignatureParser(dtm, dtms);

            // Parse the prototype into a function signature
            ghidra.program.model.data.FunctionDefinitionDataType sig = parser.parse(null, prototype);

            if (sig == null) {
                String msg = "Failed to parse function prototype";
                errorMessage.append(msg);
                Msg.error(this, msg);
                return;
            }

            // Create and apply the command
            ghidra.app.cmd.function.ApplyFunctionSignatureCmd cmd = 
                new ghidra.app.cmd.function.ApplyFunctionSignatureCmd(
                    addr, sig, SourceType.USER_DEFINED);

            // Apply the command to the program
            boolean cmdResult = cmd.applyTo(program, new ConsoleTaskMonitor());

            if (cmdResult) {
                success.set(true);
                Msg.info(this, "Successfully applied function signature");
            } else {
                String msg = "Command failed: " + cmd.getStatusMsg();
                errorMessage.append(msg);
                Msg.error(this, msg);
            }
        } catch (Exception e) {
            String msg = "Error applying function signature: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        } finally {
            program.endTransaction(txProto, success.get());
        }
    }

    /**
     * Set a local variable's type using HighFunctionDBUtil.updateDBVariable
     */
    private boolean setLocalVariableType(String functionAddrStr, String variableName, String newType) {
        // Input validation
        Program program = getCurrentProgram();
        if (program == null) return false;
        if (functionAddrStr == null || functionAddrStr.isEmpty() || 
            variableName == null || variableName.isEmpty() ||
            newType == null || newType.isEmpty()) {
            return false;
        }

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> 
                applyVariableType(program, functionAddrStr, variableName, newType, success));
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute set variable type on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Helper method that performs the actual variable type change
     */
    private void applyVariableType(Program program, String functionAddrStr, 
                                  String variableName, String newType, AtomicBoolean success) {
        try {
            // Find the function
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);

            if (func == null) {
                Msg.error(this, "Could not find function at address: " + functionAddrStr);
                return;
            }

            DecompileResults results = decompileFunction(func, program);
            if (results == null || !results.decompileCompleted()) {
                return;
            }

            ghidra.program.model.pcode.HighFunction highFunction = results.getHighFunction();
            if (highFunction == null) {
                Msg.error(this, "No high function available");
                return;
            }

            // Find the symbol by name
            HighSymbol symbol = findSymbolByName(highFunction, variableName);
            if (symbol == null) {
                Msg.error(this, "Could not find variable '" + variableName + "' in decompiled function");
                return;
            }

            // Get high variable
            HighVariable highVar = symbol.getHighVariable();
            if (highVar == null) {
                Msg.error(this, "No HighVariable found for symbol: " + variableName);
                return;
            }

            Msg.info(this, "Found high variable for: " + variableName + 
                     " with current type " + highVar.getDataType().getName());

            // Find the data type
            DataTypeManager dtm = program.getDataTypeManager();
            DataType dataType = resolveDataType(dtm, newType);

            if (dataType == null) {
                Msg.error(this, "Could not resolve data type: " + newType);
                return;
            }

            Msg.info(this, "Using data type: " + dataType.getName() + " for variable " + variableName);

            // Apply the type change in a transaction
            updateVariableType(program, symbol, dataType, success);

        } catch (Exception e) {
            Msg.error(this, "Error setting variable type: " + e.getMessage());
        }
    }

    /**
     * Find a high symbol by name in the given high function
     */
    private HighSymbol findSymbolByName(ghidra.program.model.pcode.HighFunction highFunction, String variableName) {
        Iterator<HighSymbol> symbols = highFunction.getLocalSymbolMap().getSymbols();
        while (symbols.hasNext()) {
            HighSymbol s = symbols.next();
            if (s.getName().equals(variableName)) {
                return s;
            }
        }
        return null;
    }

    /**
     * Decompile a function and return the results
     */
    private DecompileResults decompileFunction(Function func, Program program) {
        // Set up decompiler for accessing the decompiled function
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);
        decomp.setSimplificationStyle("decompile"); // Full decompilation

        // Decompile the function
        DecompileResults results = decomp.decompileFunction(func, 60, new ConsoleTaskMonitor());

        if (!results.decompileCompleted()) {
            Msg.error(this, "Could not decompile function: " + results.getErrorMessage());
            return null;
        }

        return results;
    }

    /**
     * Apply the type update in a transaction
     */
    private void updateVariableType(Program program, HighSymbol symbol, DataType dataType, AtomicBoolean success) {
        int tx = program.startTransaction("Set variable type");
        try {
            // Use HighFunctionDBUtil to update the variable with the new type
            HighFunctionDBUtil.updateDBVariable(
                symbol,                // The high symbol to modify
                symbol.getName(),      // Keep original name
                dataType,              // The new data type
                SourceType.USER_DEFINED // Mark as user-defined
            );

            success.set(true);
            Msg.info(this, "Successfully set variable type using HighFunctionDBUtil");
        } catch (Exception e) {
            Msg.error(this, "Error setting variable type: " + e.getMessage());
        } finally {
            program.endTransaction(tx, success.get());
        }
    }

    /**
     * Get all references to a specific address (xref to)
     */
    private String getXrefsTo(String addressStr, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            ReferenceManager refManager = program.getReferenceManager();
            
            ReferenceIterator refIter = refManager.getReferencesTo(addr);
            
            List<String> refs = new ArrayList<>();
            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                Address fromAddr = ref.getFromAddress();
                RefType refType = ref.getReferenceType();
                
                Function fromFunc = program.getFunctionManager().getFunctionContaining(fromAddr);
                String funcInfo = (fromFunc != null) ? " in " + fromFunc.getName() : "";
                
                refs.add(String.format("From %s%s [%s]", fromAddr, funcInfo, refType.getName()));
            }
            
            return paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting references to address: " + e.getMessage();
        }
    }

    /**
     * Get all references from a specific address (xref from)
     */
    private String getXrefsFrom(String addressStr, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            ReferenceManager refManager = program.getReferenceManager();
            
            Reference[] references = refManager.getReferencesFrom(addr);
            
            List<String> refs = new ArrayList<>();
            for (Reference ref : references) {
                Address toAddr = ref.getToAddress();
                RefType refType = ref.getReferenceType();
                
                String targetInfo = "";
                Function toFunc = program.getFunctionManager().getFunctionAt(toAddr);
                if (toFunc != null) {
                    targetInfo = " to function " + toFunc.getName();
                } else {
                    Data data = program.getListing().getDataAt(toAddr);
                    if (data != null) {
                        targetInfo = " to data " + (data.getLabel() != null ? data.getLabel() : data.getPathName());
                    }
                }
                
                refs.add(String.format("To %s%s [%s]", toAddr, targetInfo, refType.getName()));
            }
            
            return paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting references from address: " + e.getMessage();
        }
    }

    /**
     * Get all references to a specific function by name
     */
    private String getFunctionXrefs(String functionName, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (functionName == null || functionName.isEmpty()) return "Function name is required";

        try {
            Function function = findFunctionByName(program, functionName);
            if (function == null) {
                return "No references found to function: " + functionName;
            }

            List<String> refs = new ArrayList<>();
            FunctionManager funcManager = program.getFunctionManager();
            Address entryPoint = function.getEntryPoint();
            ReferenceIterator refIter = program.getReferenceManager().getReferencesTo(entryPoint);

            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                Address fromAddr = ref.getFromAddress();
                RefType refType = ref.getReferenceType();

                Function fromFunc = funcManager.getFunctionContaining(fromAddr);
                String funcInfo = (fromFunc != null) ? " in " + getFullyQualifiedFunctionName(fromFunc) : "";

                refs.add(String.format("From %s%s [%s]", fromAddr, funcInfo, refType.getName()));
            }

            if (refs.isEmpty()) {
                return "No references found to function: " + functionName;
            }

            return paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting function references: " + e.getMessage();
        }
    }

/**
 * List all defined strings in the program with their addresses
 */
    private String listDefinedStrings(int offset, int limit, String filter) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        DataIterator dataIt = program.getListing().getDefinedData(true);
        
        while (dataIt.hasNext()) {
            Data data = dataIt.next();
            
            if (data != null && isStringData(data)) {
                String value = data.getValue() != null ? data.getValue().toString() : "";
                
                if (filter == null || value.toLowerCase().contains(filter.toLowerCase())) {
                    String escapedValue = escapeString(value);
                    lines.add(String.format("%s: \"%s\"", data.getAddress(), escapedValue));
                }
            }
        }
        
        return paginateList(lines, offset, limit);
    }

    /**
     * Check if the given data is a string type
     */
    private boolean isStringData(Data data) {
        if (data == null) return false;
        
        DataType dt = data.getDataType();
        String typeName = dt.getName().toLowerCase();
        return typeName.contains("string") || typeName.contains("char") || typeName.equals("unicode");
    }

    /**
     * Escape special characters in a string for display
     */
    private String escapeString(String input) {
        if (input == null) return "";
        
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (c >= 32 && c < 127) {
                sb.append(c);
            } else if (c == '\n') {
                sb.append("\\n");
            } else if (c == '\r') {
                sb.append("\\r");
            } else if (c == '\t') {
                sb.append("\\t");
            } else {
                sb.append(String.format("\\x%02x", (int)c & 0xFF));
            }
        }
        return sb.toString();
    }

    /**
     * Resolves a data type by name, handling common types and pointer types
     * @param dtm The data type manager
     * @param typeName The type name to resolve
     * @return The resolved DataType, or null if not found
     */
    private DataType resolveDataType(DataTypeManager dtm, String typeName) {
        // First try to find exact match in all categories
        DataType dataType = findDataTypeByNameInAllCategories(dtm, typeName);
        if (dataType != null) {
            Msg.info(this, "Found exact data type match: " + dataType.getPathName());
            return dataType;
        }

        // Check for C-style pointer types (type*)
        if (typeName.endsWith("*")) {
            String baseTypeName = typeName.substring(0, typeName.length() - 1).trim();
            if (baseTypeName.isEmpty()) {
                return new PointerDataType(dtm.getDataType("/void"));
            }
            DataType baseType = resolveDataType(dtm, baseTypeName);
            if (baseType != null) {
                return new PointerDataType(baseType);
            }
            Msg.warn(this, "Base type not found for pointer: " + typeName + ", defaulting to void*");
            return new PointerDataType(dtm.getDataType("/void"));
        }

        // Check for Windows-style pointer types (PXXX)
        if (typeName.startsWith("P") && typeName.length() > 1) {
            String baseTypeName = typeName.substring(1);

            // Special case for PVOID
            if (baseTypeName.equals("VOID")) {
                return new PointerDataType(dtm.getDataType("/void"));
            }

            // Try to find the base type
            DataType baseType = findDataTypeByNameInAllCategories(dtm, baseTypeName);
            if (baseType != null) {
                return new PointerDataType(baseType);
            }

            Msg.warn(this, "Base type not found for " + typeName + ", defaulting to void*");
            return new PointerDataType(dtm.getDataType("/void"));
        }

        // Handle common built-in types
        switch (typeName.toLowerCase()) {
            case "int":
            case "long":
                return dtm.getDataType("/int");
            case "uint":
            case "unsigned int":
            case "unsigned long":
            case "dword":
                return dtm.getDataType("/uint");
            case "short":
                return dtm.getDataType("/short");
            case "ushort":
            case "unsigned short":
            case "word":
                return dtm.getDataType("/ushort");
            case "char":
            case "byte":
                return dtm.getDataType("/char");
            case "uchar":
            case "unsigned char":
                return dtm.getDataType("/uchar");
            case "longlong":
            case "__int64":
                return dtm.getDataType("/longlong");
            case "ulonglong":
            case "unsigned __int64":
                return dtm.getDataType("/ulonglong");
            case "bool":
            case "boolean":
                return dtm.getDataType("/bool");
            case "void":
                return dtm.getDataType("/void");
            default:
                // Try as a direct path
                DataType directType = dtm.getDataType("/" + typeName);
                if (directType != null) {
                    return directType;
                }

                // Fallback to int if we couldn't find it
                Msg.warn(this, "Unknown type: " + typeName + ", defaulting to int");
                return dtm.getDataType("/int");
        }
    }
    
    /**
     * Find a data type by name in all categories/folders of the data type manager
     * This searches through all categories rather than just the root
     */
    private DataType findDataTypeByNameInAllCategories(DataTypeManager dtm, String typeName) {
        // Try exact match first
        DataType result = searchByNameInAllCategories(dtm, typeName);
        if (result != null) {
            return result;
        }

        // Try lowercase
        return searchByNameInAllCategories(dtm, typeName.toLowerCase());
    }

    /**
     * Helper method to search for a data type by name in all categories
     */
    private DataType searchByNameInAllCategories(DataTypeManager dtm, String name) {
        // Get all data types from the manager
        Iterator<DataType> allTypes = dtm.getAllDataTypes();
        while (allTypes.hasNext()) {
            DataType dt = allTypes.next();
            // Check if the name matches exactly (case-sensitive) 
            if (dt.getName().equals(name)) {
                return dt;
            }
            // For case-insensitive, we want an exact match except for case
            if (dt.getName().equalsIgnoreCase(name)) {
                return dt;
            }
        }
        return null;
    }

    /**
     * Find a Structure data type by name in all categories.
     */
    private Structure findStructureByName(DataTypeManager dtm, String name) {
        DataType dt = findDataTypeByNameInAllCategories(dtm, name);
        if (dt instanceof Structure) {
            return (Structure) dt;
        }
        return null;
    }

    /**
     * Find a Union data type by name in all categories.
     */
    private Union findUnionByName(DataTypeManager dtm, String name) {
        DataType dt = findDataTypeByNameInAllCategories(dtm, name);
        if (dt instanceof Union) {
            return (Union) dt;
        }
        return null;
    }

    /**
     * Find an Enum data type by name in all categories.
     */
    private ghidra.program.model.data.Enum findEnumByName(DataTypeManager dtm, String name) {
        DataType dt = findDataTypeByNameInAllCategories(dtm, name);
        if (dt instanceof ghidra.program.model.data.Enum) {
            return (ghidra.program.model.data.Enum) dt;
        }
        return null;
    }

    // ----------------------------------------------------------------------------------
    // Namespace management endpoints
    // ----------------------------------------------------------------------------------

    /**
     * Create a namespace hierarchy from a :: delimited path.
     */
    private String createNamespace(String namespacePath) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (namespacePath == null || namespacePath.isEmpty()) return "Namespace path is required";

        final StringBuilder result = new StringBuilder();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create namespace");
                boolean success = false;
                try {
                    Namespace ns = NamespaceUtils.createNamespaceHierarchy(
                        namespacePath, null, program, SourceType.USER_DEFINED);
                    result.append("Created namespace: ").append(ns.getName(true));
                    success = true;
                } catch (Exception e) {
                    result.append("Error creating namespace: ").append(e.getMessage());
                    Msg.error(this, "Error creating namespace", e);
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            return "Failed to create namespace on Swing thread: " + e.getMessage();
        }
        return result.toString();
    }

    /**
     * Move the primary symbol at a given address into a namespace.
     */
    private String moveSymbolToNamespace(String addressStr, String namespacePath) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";
        if (namespacePath == null || namespacePath.isEmpty()) return "Namespace path is required";

        final StringBuilder result = new StringBuilder();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Move symbol to namespace");
                boolean success = false;
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    Symbol symbol = program.getSymbolTable().getPrimarySymbol(addr);
                    if (symbol == null) {
                        result.append("No symbol found at address: ").append(addressStr);
                        return;
                    }
                    Namespace targetNs = NamespaceUtils.createNamespaceHierarchy(
                        namespacePath, null, program, SourceType.USER_DEFINED);
                    symbol.setNamespace(targetNs);
                    result.append("Moved ").append(symbol.getName())
                          .append(" to ").append(targetNs.getName(true));
                    success = true;
                } catch (Exception e) {
                    result.append("Error moving symbol: ").append(e.getMessage());
                    Msg.error(this, "Error moving symbol to namespace", e);
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            return "Failed to move symbol on Swing thread: " + e.getMessage();
        }
        return result.toString();
    }

    /**
     * List the contents (symbols) of a namespace.
     */
    private String listNamespaceContents(String namespacePath, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (namespacePath == null || namespacePath.isEmpty()) return "Namespace path is required";

        List<Namespace> nsList = NamespaceUtils.getNamespaceByPath(program, null, namespacePath);
        if (nsList == null || nsList.isEmpty()) {
            return "Namespace not found: " + namespacePath;
        }
        Namespace ns = nsList.get(0);

        List<String> lines = new ArrayList<>();
        SymbolIterator symIter = program.getSymbolTable().getSymbols(ns);
        while (symIter.hasNext()) {
            Symbol sym = symIter.next();
            lines.add(String.format("%s [%s] @ %s",
                sym.getName(), sym.getSymbolType().toString(), sym.getAddress()));
        }

        if (lines.isEmpty()) {
            return "Namespace is empty: " + namespacePath;
        }
        return paginateList(lines, offset, limit);
    }

    // ----------------------------------------------------------------------------------
    // Data structure management methods
    // ----------------------------------------------------------------------------------

    /**
     * Create a new structure data type.
     */
    private String createStruct(String name, int size, String categoryPath) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (name == null || name.isEmpty()) return "Structure name is required";
        if (size <= 0) return "Structure size must be a positive integer";

        if (categoryPath == null || categoryPath.isEmpty()) {
            categoryPath = "/";
        }
        final String catPath = categoryPath;

        final StringBuilder result = new StringBuilder();
        try {
            SwingUtilities.invokeAndWait(() -> {
                DataTypeManager dtm = program.getDataTypeManager();
                int tx = program.startTransaction("Create struct: " + name);
                boolean success = false;
                try {
                    StructureDataType struct = new StructureDataType(new CategoryPath(catPath), name, size, dtm);
                    dtm.addDataType(struct, DataTypeConflictHandler.DEFAULT_HANDLER);
                    result.append("Created structure: ").append(name).append(" (").append(size).append(" bytes)");
                    success = true;
                } catch (Exception e) {
                    result.append("Error creating structure: ").append(e.getMessage());
                    Msg.error(this, "Error creating structure", e);
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            return "Failed to create structure on Swing thread: " + e.getMessage();
        }
        return result.toString();
    }

    /**
     * Add or replace a field at a specific offset in a structure.
     */
    private String addStructField(String structName, int offset, String fieldType, String fieldName, int fieldLength, String comment) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (structName == null || structName.isEmpty()) return "Structure name is required";
        if (offset < 0) return "Field offset is required and must be non-negative";
        if (fieldType == null || fieldType.isEmpty()) return "Field type is required";
        if (fieldName == null || fieldName.isEmpty()) return "Field name is required";

        final StringBuilder result = new StringBuilder();
        try {
            SwingUtilities.invokeAndWait(() -> {
                DataTypeManager dtm = program.getDataTypeManager();
                int tx = program.startTransaction("Add struct field: " + fieldName);
                boolean success = false;
                try {
                    Structure struct = findStructureByName(dtm, structName);
                    if (struct == null) {
                        result.append("Structure not found: ").append(structName);
                        return;
                    }
                    DataType dataType = resolveDataType(dtm, fieldType);
                    if (dataType == null) {
                        result.append("Could not resolve field type: ").append(fieldType);
                        return;
                    }
                    int length = fieldLength > 0 ? fieldLength : dataType.getLength();
                    struct.replaceAtOffset(offset, dataType, length, fieldName, comment);
                    result.append("Added field '").append(fieldName).append("' at offset ").append(offset)
                          .append(" in struct '").append(structName).append("'");
                    success = true;
                } catch (Exception e) {
                    result.append("Error adding struct field: ").append(e.getMessage());
                    Msg.error(this, "Error adding struct field", e);
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            return "Failed to add struct field on Swing thread: " + e.getMessage();
        }
        return result.toString();
    }

    /**
     * Delete (clear) a field at a specific offset in a structure.
     */
    private String deleteStructField(String structName, int offset) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (structName == null || structName.isEmpty()) return "Structure name is required";
        if (offset < 0) return "Field offset is required and must be non-negative";

        final StringBuilder result = new StringBuilder();
        try {
            SwingUtilities.invokeAndWait(() -> {
                DataTypeManager dtm = program.getDataTypeManager();
                int tx = program.startTransaction("Delete struct field at offset " + offset);
                boolean success = false;
                try {
                    Structure struct = findStructureByName(dtm, structName);
                    if (struct == null) {
                        result.append("Structure not found: ").append(structName);
                        return;
                    }
                    struct.clearAtOffset(offset);
                    result.append("Cleared field at offset ").append(offset)
                          .append(" in struct '").append(structName).append("'");
                    success = true;
                } catch (Exception e) {
                    result.append("Error deleting struct field: ").append(e.getMessage());
                    Msg.error(this, "Error deleting struct field", e);
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            return "Failed to delete struct field on Swing thread: " + e.getMessage();
        }
        return result.toString();
    }

    /**
     * Get all defined fields of a structure.
     */
    private String getStructFields(String structName, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (structName == null || structName.isEmpty()) return "Structure name is required";

        DataTypeManager dtm = program.getDataTypeManager();
        Structure struct = findStructureByName(dtm, structName);
        if (struct == null) return "Structure not found: " + structName;

        DataTypeComponent[] components = struct.getDefinedComponents();
        List<String> lines = new ArrayList<>();
        for (DataTypeComponent comp : components) {
            String fieldName = comp.getFieldName() != null ? comp.getFieldName() : "(unnamed)";
            String comment = comp.getComment() != null ? comp.getComment() : "";
            lines.add(String.format("Offset: %d, Type: %s, Name: %s, Length: %d, Comment: %s",
                comp.getOffset(), comp.getDataType().getName(), fieldName, comp.getLength(), comment));
        }

        if (lines.isEmpty()) {
            return "Structure '" + structName + "' has no defined fields (size: " + struct.getLength() + " bytes)";
        }
        return paginateList(lines, offset, limit);
    }

    /**
     * Create a new union data type.
     */
    private String createUnion(String name, String categoryPath) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (name == null || name.isEmpty()) return "Union name is required";

        if (categoryPath == null || categoryPath.isEmpty()) {
            categoryPath = "/";
        }
        final String catPath = categoryPath;

        final StringBuilder result = new StringBuilder();
        try {
            SwingUtilities.invokeAndWait(() -> {
                DataTypeManager dtm = program.getDataTypeManager();
                int tx = program.startTransaction("Create union: " + name);
                boolean success = false;
                try {
                    UnionDataType union = new UnionDataType(new CategoryPath(catPath), name, dtm);
                    dtm.addDataType(union, DataTypeConflictHandler.DEFAULT_HANDLER);
                    result.append("Created union: ").append(name);
                    success = true;
                } catch (Exception e) {
                    result.append("Error creating union: ").append(e.getMessage());
                    Msg.error(this, "Error creating union", e);
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            return "Failed to create union on Swing thread: " + e.getMessage();
        }
        return result.toString();
    }

    /**
     * Add a field to a union data type.
     */
    private String addUnionField(String unionName, String fieldType, String fieldName, int fieldLength, String comment) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (unionName == null || unionName.isEmpty()) return "Union name is required";
        if (fieldType == null || fieldType.isEmpty()) return "Field type is required";
        if (fieldName == null || fieldName.isEmpty()) return "Field name is required";

        final StringBuilder result = new StringBuilder();
        try {
            SwingUtilities.invokeAndWait(() -> {
                DataTypeManager dtm = program.getDataTypeManager();
                int tx = program.startTransaction("Add union field: " + fieldName);
                boolean success = false;
                try {
                    Union union = findUnionByName(dtm, unionName);
                    if (union == null) {
                        result.append("Union not found: ").append(unionName);
                        return;
                    }
                    DataType dataType = resolveDataType(dtm, fieldType);
                    if (dataType == null) {
                        result.append("Could not resolve field type: ").append(fieldType);
                        return;
                    }
                    int length = fieldLength > 0 ? fieldLength : dataType.getLength();
                    union.add(dataType, length, fieldName, comment);
                    result.append("Added field '").append(fieldName).append("' to union '").append(unionName).append("'");
                    success = true;
                } catch (Exception e) {
                    result.append("Error adding union field: ").append(e.getMessage());
                    Msg.error(this, "Error adding union field", e);
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            return "Failed to add union field on Swing thread: " + e.getMessage();
        }
        return result.toString();
    }

    /**
     * Create a new enum data type.
     */
    private String createEnum(String name, int size, String categoryPath) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (name == null || name.isEmpty()) return "Enum name is required";
        if (size != 1 && size != 2 && size != 4 && size != 8) return "Enum size must be 1, 2, 4, or 8 bytes";

        if (categoryPath == null || categoryPath.isEmpty()) {
            categoryPath = "/";
        }
        final String catPath = categoryPath;

        final StringBuilder result = new StringBuilder();
        try {
            SwingUtilities.invokeAndWait(() -> {
                DataTypeManager dtm = program.getDataTypeManager();
                int tx = program.startTransaction("Create enum: " + name);
                boolean success = false;
                try {
                    EnumDataType enumDt = new EnumDataType(new CategoryPath(catPath), name, size, dtm);
                    dtm.addDataType(enumDt, DataTypeConflictHandler.DEFAULT_HANDLER);
                    result.append("Created enum: ").append(name).append(" (").append(size).append(" bytes)");
                    success = true;
                } catch (Exception e) {
                    result.append("Error creating enum: ").append(e.getMessage());
                    Msg.error(this, "Error creating enum", e);
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            return "Failed to create enum on Swing thread: " + e.getMessage();
        }
        return result.toString();
    }

    /**
     * Add a named value to an enum data type.
     */
    private String addEnumValue(String enumName, String entryName, long value) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (enumName == null || enumName.isEmpty()) return "Enum name is required";
        if (entryName == null || entryName.isEmpty()) return "Entry name is required";

        final StringBuilder result = new StringBuilder();
        try {
            SwingUtilities.invokeAndWait(() -> {
                DataTypeManager dtm = program.getDataTypeManager();
                int tx = program.startTransaction("Add enum value: " + entryName);
                boolean success = false;
                try {
                    ghidra.program.model.data.Enum enumDt = findEnumByName(dtm, enumName);
                    if (enumDt == null) {
                        result.append("Enum not found: ").append(enumName);
                        return;
                    }
                    enumDt.add(entryName, value);
                    result.append("Added value '").append(entryName).append("' = ").append(value)
                          .append(" to enum '").append(enumName).append("'");
                    success = true;
                } catch (Exception e) {
                    result.append("Error adding enum value: ").append(e.getMessage());
                    Msg.error(this, "Error adding enum value", e);
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            return "Failed to add enum value on Swing thread: " + e.getMessage();
        }
        return result.toString();
    }

    /**
     * Get detailed information about a data type by name.
     */
    private String getDataTypeInfo(String name) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (name == null || name.isEmpty()) return "Data type name is required";

        DataTypeManager dtm = program.getDataTypeManager();
        DataType dt = findDataTypeByNameInAllCategories(dtm, name);
        if (dt == null) return "Data type not found: " + name;

        StringBuilder sb = new StringBuilder();
        sb.append("Name: ").append(dt.getName()).append("\n");
        sb.append("Category: ").append(dt.getCategoryPath()).append("\n");
        sb.append("Length: ").append(dt.getLength()).append(" bytes\n");

        if (dt instanceof Structure) {
            Structure struct = (Structure) dt;
            sb.append("Type: Structure\n");
            sb.append("Alignment: ").append(struct.getAlignment()).append("\n");
            DataTypeComponent[] components = struct.getDefinedComponents();
            sb.append("Fields (").append(components.length).append("):\n");
            for (DataTypeComponent comp : components) {
                String fieldName = comp.getFieldName() != null ? comp.getFieldName() : "(unnamed)";
                String comment = comp.getComment() != null ? comp.getComment() : "";
                sb.append(String.format("  Offset: %d, Type: %s, Name: %s, Length: %d, Comment: %s\n",
                    comp.getOffset(), comp.getDataType().getName(), fieldName, comp.getLength(), comment));
            }
        } else if (dt instanceof Union) {
            Union union = (Union) dt;
            sb.append("Type: Union\n");
            DataTypeComponent[] components = union.getDefinedComponents();
            sb.append("Fields (").append(components.length).append("):\n");
            for (int i = 0; i < components.length; i++) {
                DataTypeComponent comp = components[i];
                String fieldName = comp.getFieldName() != null ? comp.getFieldName() : "(unnamed)";
                String comment = comp.getComment() != null ? comp.getComment() : "";
                sb.append(String.format("  Ordinal: %d, Type: %s, Name: %s, Length: %d, Comment: %s\n",
                    comp.getOrdinal(), comp.getDataType().getName(), fieldName, comp.getLength(), comment));
            }
        } else if (dt instanceof ghidra.program.model.data.Enum) {
            ghidra.program.model.data.Enum enumDt = (ghidra.program.model.data.Enum) dt;
            sb.append("Type: Enum\n");
            String[] names = enumDt.getNames();
            sb.append("Values (").append(names.length).append("):\n");
            for (String n : names) {
                sb.append(String.format("  %s = %d\n", n, enumDt.getValue(n)));
            }
        } else {
            sb.append("Type: ").append(dt.getClass().getSimpleName()).append("\n");
            if (dt.getDescription() != null && !dt.getDescription().isEmpty()) {
                sb.append("Description: ").append(dt.getDescription()).append("\n");
            }
        }

        return sb.toString().stripTrailing();
    }

    /**
     * Apply a structure data type at a specific address.
     */
    private String applyStructToAddress(String addressStr, String structName) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";
        if (structName == null || structName.isEmpty()) return "Structure name is required";

        final StringBuilder result = new StringBuilder();
        try {
            SwingUtilities.invokeAndWait(() -> {
                DataTypeManager dtm = program.getDataTypeManager();
                int tx = program.startTransaction("Apply struct at address");
                boolean success = false;
                try {
                    Structure struct = findStructureByName(dtm, structName);
                    if (struct == null) {
                        result.append("Structure not found: ").append(structName);
                        return;
                    }
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    if (addr == null) {
                        result.append("Invalid address: ").append(addressStr);
                        return;
                    }
                    program.getListing().clearCodeUnits(addr, addr.add(struct.getLength() - 1), false);
                    program.getListing().createData(addr, struct);
                    result.append("Applied struct '").append(structName).append("' at address ").append(addressStr);
                    success = true;
                } catch (Exception e) {
                    result.append("Error applying struct: ").append(e.getMessage());
                    Msg.error(this, "Error applying struct to address", e);
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            return "Failed to apply struct on Swing thread: " + e.getMessage();
        }
        return result.toString();
    }

    // ----------------------------------------------------------------------------------
    // Function signature refactoring methods
    // ----------------------------------------------------------------------------------

    /**
     * Get detailed signature information for a function at the given address.
     */
    private String getFunctionSignatureDetails(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) return "Invalid address: " + addressStr;

            Function func = program.getFunctionManager().getFunctionAt(addr);
            if (func == null) return "No function found at address " + addressStr;

            StringBuilder sb = new StringBuilder();
            sb.append("Prototype: ").append(func.getSignature().getPrototypeString()).append("\n");
            sb.append("Return Type: ").append(func.getReturnType().getName()).append("\n");
            sb.append("Calling Convention: ").append(func.getCallingConventionName()).append("\n");
            sb.append("Parameter Count: ").append(func.getParameterCount()).append("\n");

            Parameter[] params = func.getParameters();
            for (int i = 0; i < params.length; i++) {
                Parameter p = params[i];
                sb.append("Param ").append(i).append(": ")
                  .append(p.getDataType().getName()).append(" ")
                  .append(p.getName())
                  .append(" (ordinal=").append(p.getOrdinal())
                  .append(", storage=").append(p.getVariableStorage())
                  .append(")\n");
            }

            return sb.toString().stripTrailing();
        } catch (Exception e) {
            return "Error getting function signature: " + e.getMessage();
        }
    }

    /**
     * Set the return type of a function at the given address.
     */
    private String setFunctionReturnType(String addressStr, String returnTypeName) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Function address is required";
        if (returnTypeName == null || returnTypeName.isEmpty()) return "Return type is required";

        final StringBuilder result = new StringBuilder();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Set return type");
                boolean success = false;
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    if (addr == null) {
                        result.append("Invalid address: ").append(addressStr);
                        return;
                    }
                    Function func = program.getFunctionManager().getFunctionAt(addr);
                    if (func == null) {
                        result.append("No function found at address ").append(addressStr);
                        return;
                    }
                    DataTypeManager dtm = program.getDataTypeManager();
                    DataType dataType = resolveDataType(dtm, returnTypeName);
                    if (dataType == null) {
                        result.append("Could not resolve return type: ").append(returnTypeName);
                        return;
                    }
                    func.setReturnType(dataType, SourceType.USER_DEFINED);
                    result.append("Set return type of '").append(func.getName())
                          .append("' to '").append(returnTypeName).append("'");
                    success = true;
                } catch (Exception e) {
                    result.append("Error setting return type: ").append(e.getMessage());
                    Msg.error(this, "Error setting return type", e);
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            return "Failed to set return type on Swing thread: " + e.getMessage();
        }
        return result.toString();
    }

    /**
     * Add a parameter to a function at the given address.
     */
    private String addFunctionParameter(String addressStr, String paramName, String paramType, int index) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Function address is required";
        if (paramName == null || paramName.isEmpty()) return "Parameter name is required";
        if (paramType == null || paramType.isEmpty()) return "Parameter type is required";

        final StringBuilder result = new StringBuilder();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Add parameter");
                boolean success = false;
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    if (addr == null) {
                        result.append("Invalid address: ").append(addressStr);
                        return;
                    }
                    Function func = program.getFunctionManager().getFunctionAt(addr);
                    if (func == null) {
                        result.append("No function found at address ").append(addressStr);
                        return;
                    }
                    DataTypeManager dtm = program.getDataTypeManager();
                    DataType dataType = resolveDataType(dtm, paramType);
                    if (dataType == null) {
                        result.append("Could not resolve parameter type: ").append(paramType);
                        return;
                    }
                    ParameterImpl param = new ParameterImpl(paramName, dataType, program);
                    if (index >= 0) {
                        func.insertParameter(index, param, SourceType.USER_DEFINED);
                    } else {
                        func.addParameter(param, SourceType.USER_DEFINED);
                    }
                    result.append("Added parameter '").append(paramName)
                          .append("' of type '").append(paramType)
                          .append("' to '").append(func.getName()).append("'");
                    success = true;
                } catch (Exception e) {
                    result.append("Error adding parameter: ").append(e.getMessage());
                    Msg.error(this, "Error adding parameter", e);
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            return "Failed to add parameter on Swing thread: " + e.getMessage();
        }
        return result.toString();
    }

    /**
     * Remove a parameter from a function at the given address by index.
     */
    private String removeFunctionParameter(String addressStr, int index) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Function address is required";
        if (index < 0) return "Parameter index is required and must be non-negative";

        final StringBuilder result = new StringBuilder();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Remove parameter");
                boolean success = false;
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    if (addr == null) {
                        result.append("Invalid address: ").append(addressStr);
                        return;
                    }
                    Function func = program.getFunctionManager().getFunctionAt(addr);
                    if (func == null) {
                        result.append("No function found at address ").append(addressStr);
                        return;
                    }
                    if (index >= func.getParameterCount()) {
                        result.append("Parameter index ").append(index)
                              .append(" out of range (function has ").append(func.getParameterCount())
                              .append(" parameters)");
                        return;
                    }
                    func.removeParameter(index);
                    result.append("Removed parameter at index ").append(index)
                          .append(" from '").append(func.getName()).append("'");
                    success = true;
                } catch (Exception e) {
                    result.append("Error removing parameter: ").append(e.getMessage());
                    Msg.error(this, "Error removing parameter", e);
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            return "Failed to remove parameter on Swing thread: " + e.getMessage();
        }
        return result.toString();
    }

    /**
     * Change the data type of a function parameter at the given index.
     */
    private String changeFunctionParameterType(String addressStr, int index, String newTypeName) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Function address is required";
        if (index < 0) return "Parameter index is required and must be non-negative";
        if (newTypeName == null || newTypeName.isEmpty()) return "New type name is required";

        final StringBuilder result = new StringBuilder();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Change parameter type");
                boolean success = false;
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    if (addr == null) {
                        result.append("Invalid address: ").append(addressStr);
                        return;
                    }
                    Function func = program.getFunctionManager().getFunctionAt(addr);
                    if (func == null) {
                        result.append("No function found at address ").append(addressStr);
                        return;
                    }
                    if (index >= func.getParameterCount()) {
                        result.append("Parameter index ").append(index)
                              .append(" out of range (function has ").append(func.getParameterCount())
                              .append(" parameters)");
                        return;
                    }
                    DataTypeManager dtm = program.getDataTypeManager();
                    DataType dataType = resolveDataType(dtm, newTypeName);
                    if (dataType == null) {
                        result.append("Could not resolve type: ").append(newTypeName);
                        return;
                    }
                    func.getParameter(index).setDataType(dataType, SourceType.USER_DEFINED);
                    result.append("Changed type of parameter ").append(index)
                          .append(" to '").append(newTypeName)
                          .append("' in '").append(func.getName()).append("'");
                    success = true;
                } catch (Exception e) {
                    result.append("Error changing parameter type: ").append(e.getMessage());
                    Msg.error(this, "Error changing parameter type", e);
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            return "Failed to change parameter type on Swing thread: " + e.getMessage();
        }
        return result.toString();
    }

    /**
     * Rename a function parameter at the given index.
     */
    private String renameFunctionParameter(String addressStr, int index, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Function address is required";
        if (index < 0) return "Parameter index is required and must be non-negative";
        if (newName == null || newName.isEmpty()) return "New parameter name is required";

        final StringBuilder result = new StringBuilder();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename parameter");
                boolean success = false;
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    if (addr == null) {
                        result.append("Invalid address: ").append(addressStr);
                        return;
                    }
                    Function func = program.getFunctionManager().getFunctionAt(addr);
                    if (func == null) {
                        result.append("No function found at address ").append(addressStr);
                        return;
                    }
                    if (index >= func.getParameterCount()) {
                        result.append("Parameter index ").append(index)
                              .append(" out of range (function has ").append(func.getParameterCount())
                              .append(" parameters)");
                        return;
                    }
                    func.getParameter(index).setName(newName, SourceType.USER_DEFINED);
                    result.append("Renamed parameter ").append(index)
                          .append(" to '").append(newName)
                          .append("' in '").append(func.getName()).append("'");
                    success = true;
                } catch (Exception e) {
                    result.append("Error renaming parameter: ").append(e.getMessage());
                    Msg.error(this, "Error renaming parameter", e);
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            return "Failed to rename parameter on Swing thread: " + e.getMessage();
        }
        return result.toString();
    }

    /**
     * Set the calling convention of a function at the given address.
     */
    private String setFunctionCallingConvention(String addressStr, String convention) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Function address is required";
        if (convention == null || convention.isEmpty()) return "Calling convention is required";

        final StringBuilder result = new StringBuilder();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Set calling convention");
                boolean success = false;
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    if (addr == null) {
                        result.append("Invalid address: ").append(addressStr);
                        return;
                    }
                    Function func = program.getFunctionManager().getFunctionAt(addr);
                    if (func == null) {
                        result.append("No function found at address ").append(addressStr);
                        return;
                    }
                    func.setCallingConvention(convention);
                    result.append("Set calling convention of '").append(func.getName())
                          .append("' to '").append(convention).append("'");
                    success = true;
                } catch (Exception e) {
                    result.append("Error setting calling convention: ").append(e.getMessage());
                    Msg.error(this, "Error setting calling convention", e);
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            return "Failed to set calling convention on Swing thread: " + e.getMessage();
        }
        return result.toString();
    }

    // ----------------------------------------------------------------------------------
    // Namespace utilities
    // ----------------------------------------------------------------------------------

    /**
     * Simple holder for a resolved namespace + simple name pair.
     */
    private static class NamespacedName {
        final Namespace namespace;
        final String simpleName;

        NamespacedName(Namespace namespace, String simpleName) {
            this.namespace = namespace;
            this.simpleName = simpleName;
        }
    }

    /**
     * Find the index of the last "::" delimiter that is NOT inside angle brackets.
     * This correctly handles C++ template/generic names like:
     *   "jag::script::push_stack<jag::engine::Tile>"
     *   "std::vector<std::pair<int, int>>"
     *   "ns::Foo<ns::Bar<ns::Baz>>"
     *
     * Scans left-to-right tracking angle bracket depth (<> nesting).
     * Records the position of each "::" found at depth 0. Returns the
     * last such position, or -1 if no "::" exists outside brackets.
     */
    private int lastDelimiterOutsideBrackets(String name) {
        int lastPos = -1;
        int depth = 0;

        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            if (c == '<') {
                depth++;
            } else if (c == '>') {
                if (depth > 0) {
                    depth--;
                }
            } else if (depth == 0 && c == ':' && i + 1 < name.length() && name.charAt(i + 1) == ':') {
                lastPos = i;
                i++; // skip the second ':'
            }
        }
        return lastPos;
    }

    /**
     * If qualifiedName contains "::" outside of angle brackets, splits it into
     * namespace path and simple name, creates/gets the namespace hierarchy,
     * and returns a NamespacedName.
     * Returns null if no "::" is present outside angle brackets (caller should
     * use legacy path).
     */
    private NamespacedName resolveNamespacedName(Program program, String qualifiedName)
            throws InvalidInputException, DuplicateNameException {
        int lastDelim = lastDelimiterOutsideBrackets(qualifiedName);
        if (lastDelim < 0) {
            return null;
        }
        String namespacePath = qualifiedName.substring(0, lastDelim);
        String simpleName = qualifiedName.substring(lastDelim + Namespace.DELIMITER.length());

        Namespace targetNs = NamespaceUtils.createNamespaceHierarchy(
            namespacePath, null, program, SourceType.USER_DEFINED);
        return new NamespacedName(targetNs, simpleName);
    }

    /**
     * Find a function by name. If the name contains "::" outside angle brackets,
     * uses NamespaceUtils.getSymbols() to look up by qualified name.
     * Otherwise falls back to iterating all functions by simple name.
     * This correctly handles C++ template names where "::" may appear inside
     * angle brackets (e.g. "push_stack<jag::engine::Tile>").
     */
    private Function findFunctionByName(Program program, String name) {
        if (lastDelimiterOutsideBrackets(name) >= 0) {
            List<Symbol> symbols = NamespaceUtils.getSymbols(name, program);
            for (Symbol sym : symbols) {
                if (sym.getSymbolType() == SymbolType.FUNCTION) {
                    return program.getFunctionManager().getFunctionAt(sym.getAddress());
                }
            }
            return null;
        }
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            if (f.getName().equals(name)) {
                return f;
            }
        }
        return null;
    }

    /**
     * Returns the fully-qualified name of a function including its namespace path.
     */
    private String getFullyQualifiedFunctionName(Function func) {
        return func.getSymbol().getName(true);
    }

    // ----------------------------------------------------------------------------------
    // Utility: parse query params, parse post params, pagination, etc.
    // ----------------------------------------------------------------------------------

    /**
     * Parse query parameters from the URL, e.g. ?offset=10&limit=100
     */
    private Map<String, String> parseQueryParams(HttpExchange exchange) {
        Map<String, String> result = new HashMap<>();
        String query = exchange.getRequestURI().getQuery(); // e.g. offset=10&limit=100
        if (query != null) {
            String[] pairs = query.split("&");
            for (String p : pairs) {
                String[] kv = p.split("=");
                if (kv.length == 2) {
                    // URL decode parameter values
                    try {
                        String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                        String value = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
                        result.put(key, value);
                    } catch (Exception e) {
                        Msg.error(this, "Error decoding URL parameter", e);
                    }
                }
            }
        }
        return result;
    }

    /**
     * Parse post body form params, e.g. oldName=foo&newName=bar
     */
    private Map<String, String> parsePostParams(HttpExchange exchange) throws IOException {
        byte[] body = exchange.getRequestBody().readAllBytes();
        String bodyStr = new String(body, StandardCharsets.UTF_8);
        Map<String, String> params = new HashMap<>();
        for (String pair : bodyStr.split("&")) {
            String[] kv = pair.split("=");
            if (kv.length == 2) {
                // URL decode parameter values
                try {
                    String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                    String value = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
                    params.put(key, value);
                } catch (Exception e) {
                    Msg.error(this, "Error decoding URL parameter", e);
                }
            }
        }
        return params;
    }

    /**
     * Convert a list of strings into one big newline-delimited string, applying offset & limit.
     */
    private String paginateList(List<String> items, int offset, int limit) {
        int start = Math.max(0, offset);
        int end   = Math.min(items.size(), offset + limit);

        if (start >= items.size()) {
            return ""; // no items in range
        }
        List<String> sub = items.subList(start, end);
        return String.join("\n", sub);
    }

    /**
     * Parse an integer from a string, or return defaultValue if null/invalid.
     */
    private int parseIntOrDefault(String val, int defaultValue) {
        if (val == null) return defaultValue;
        try {
            return Integer.parseInt(val);
        }
        catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    /**
     * Parse a long from a string, or return defaultValue if null/invalid.
     * Supports 0x hex prefix.
     */
    private long parseLongOrDefault(String val, long defaultValue) {
        if (val == null) return defaultValue;
        try {
            if (val.startsWith("0x") || val.startsWith("0X")) {
                return Long.parseLong(val.substring(2), 16);
            }
            return Long.parseLong(val);
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    /**
     * Escape non-ASCII chars to avoid potential decode issues.
     */
    private String escapeNonAscii(String input) {
        if (input == null) return "";
        StringBuilder sb = new StringBuilder();
        for (char c : input.toCharArray()) {
            if (c >= 32 && c < 127) {
                sb.append(c);
            }
            else {
                sb.append("\\x");
                sb.append(Integer.toHexString(c & 0xFF));
            }
        }
        return sb.toString();
    }

    public Program getCurrentProgram() {
        ProgramManager pm = tool.getService(ProgramManager.class);
        return pm != null ? pm.getCurrentProgram() : null;
    }

    private void sendResponse(HttpExchange exchange, String response) throws IOException {
        byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    @Override
    public void dispose() {
        if (server != null) {
            Msg.info(this, "Stopping GhidraMCP HTTP server...");
            server.stop(1); // Stop with a small delay (e.g., 1 second) for connections to finish
            server = null; // Nullify the reference
            Msg.info(this, "GhidraMCP HTTP server stopped.");
        }
        super.dispose();
    }
}
