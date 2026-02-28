# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "requests>=2,<3",
#     "mcp>=1.2.0,<2",
# ]
# ///

import sys
import requests
import argparse
import logging
from urllib.parse import urljoin

from mcp.server.fastmcp import FastMCP

DEFAULT_GHIDRA_SERVER = "http://127.0.0.1:8080/"

logger = logging.getLogger(__name__)

mcp = FastMCP("ghidra-mcp")

# Initialize ghidra_server_url with default value
ghidra_server_url = DEFAULT_GHIDRA_SERVER

def safe_get(endpoint: str, params: dict = None) -> list:
    """
    Perform a GET request with optional query parameters.
    """
    if params is None:
        params = {}

    url = urljoin(ghidra_server_url, endpoint)

    try:
        response = requests.get(url, params=params, timeout=5)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.splitlines()
        else:
            return [f"Error {response.status_code}: {response.text.strip()}"]
    except Exception as e:
        return [f"Request failed: {str(e)}"]

def safe_post(endpoint: str, data: dict | str) -> str:
    try:
        url = urljoin(ghidra_server_url, endpoint)
        if isinstance(data, dict):
            response = requests.post(url, data=data, timeout=5)
        else:
            response = requests.post(url, data=data.encode("utf-8"), timeout=5)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {str(e)}"

@mcp.tool()
def list_methods(offset: int = 0, limit: int = 100) -> list:
    """
    List all function names in the program with pagination.
    """
    return safe_get("methods", {"offset": offset, "limit": limit})

@mcp.tool()
def list_classes(offset: int = 0, limit: int = 100) -> list:
    """
    List all namespace/class names in the program with pagination.
    """
    return safe_get("classes", {"offset": offset, "limit": limit})

@mcp.tool()
def decompile_function(name: str) -> str:
    """
    Decompile a specific function by name and return the decompiled C code.
    """
    return safe_post("decompile", name)

@mcp.tool()
def rename_function(old_name: str, new_name: str) -> str:
    """
    Rename a function by its current name to a new user-defined name.
    Both old_name and new_name support C++ qualified names with :: delimiters
    (e.g. "jag::engine::FooBar") which will create proper namespace hierarchies.
    """
    return safe_post("renameFunction", {"oldName": old_name, "newName": new_name})

@mcp.tool()
def rename_data(address: str, new_name: str) -> str:
    """
    Rename a data label at the specified address.
    Supports C++ qualified names with :: delimiters (e.g. "jag::engine::myData")
    which will create proper namespace hierarchies.
    """
    return safe_post("renameData", {"address": address, "newName": new_name})

@mcp.tool()
def list_segments(offset: int = 0, limit: int = 100) -> list:
    """
    List all memory segments in the program with pagination.
    """
    return safe_get("segments", {"offset": offset, "limit": limit})

@mcp.tool()
def list_imports(offset: int = 0, limit: int = 100) -> list:
    """
    List imported symbols in the program with pagination.
    """
    return safe_get("imports", {"offset": offset, "limit": limit})

@mcp.tool()
def list_exports(offset: int = 0, limit: int = 100) -> list:
    """
    List exported functions/symbols with pagination.
    """
    return safe_get("exports", {"offset": offset, "limit": limit})

@mcp.tool()
def list_namespaces(offset: int = 0, limit: int = 100) -> list:
    """
    List all non-global namespaces in the program with pagination.
    Returns fully-qualified namespace paths using :: delimiters (e.g. "jag::engine").
    """
    return safe_get("namespaces", {"offset": offset, "limit": limit})

@mcp.tool()
def list_data_items(offset: int = 0, limit: int = 100) -> list:
    """
    List defined data labels and their values with pagination.
    """
    return safe_get("data", {"offset": offset, "limit": limit})

@mcp.tool()
def search_functions_by_name(query: str, offset: int = 0, limit: int = 100) -> list:
    """
    Search for functions whose name contains the given substring.
    """
    if not query:
        return ["Error: query string is required"]
    return safe_get("searchFunctions", {"query": query, "offset": offset, "limit": limit})

@mcp.tool()
def rename_variable(function_name: str, old_name: str, new_name: str) -> str:
    """
    Rename a local variable within a function.
    The function_name supports C++ qualified names with :: delimiters
    (e.g. "jag::engine::FooBar") to find functions in namespaces.
    """
    return safe_post("renameVariable", {
        "functionName": function_name,
        "oldName": old_name,
        "newName": new_name
    })

@mcp.tool()
def get_function_by_address(address: str) -> str:
    """
    Get a function by its address.
    """
    return "\n".join(safe_get("get_function_by_address", {"address": address}))

@mcp.tool()
def get_current_address() -> str:
    """
    Get the address currently selected by the user.
    """
    return "\n".join(safe_get("get_current_address"))

@mcp.tool()
def get_current_function() -> str:
    """
    Get the function currently selected by the user.
    """
    return "\n".join(safe_get("get_current_function"))

@mcp.tool()
def list_functions() -> list:
    """
    List all functions in the database.
    """
    return safe_get("list_functions")

@mcp.tool()
def decompile_function_by_address(address: str) -> str:
    """
    Decompile a function at the given address.
    """
    return "\n".join(safe_get("decompile_function", {"address": address}))

@mcp.tool()
def disassemble_function(address: str) -> list:
    """
    Get assembly code (address: instruction; comment) for a function.
    """
    return safe_get("disassemble_function", {"address": address})

@mcp.tool()
def set_decompiler_comment(address: str, comment: str) -> str:
    """
    Set a comment for a given address in the function pseudocode.
    """
    return safe_post("set_decompiler_comment", {"address": address, "comment": comment})

@mcp.tool()
def set_disassembly_comment(address: str, comment: str) -> str:
    """
    Set a comment for a given address in the function disassembly.
    """
    return safe_post("set_disassembly_comment", {"address": address, "comment": comment})

@mcp.tool()
def rename_function_by_address(function_address: str, new_name: str) -> str:
    """
    Rename a function by its address.
    Supports C++ qualified names with :: delimiters (e.g. "jag::engine::FooBar")
    which will create proper namespace hierarchies.
    """
    return safe_post("rename_function_by_address", {"function_address": function_address, "new_name": new_name})

@mcp.tool()
def set_function_prototype(function_address: str, prototype: str) -> str:
    """
    Set a function's prototype.
    """
    return safe_post("set_function_prototype", {"function_address": function_address, "prototype": prototype})

@mcp.tool()
def set_local_variable_type(function_address: str, variable_name: str, new_type: str) -> str:
    """
    Set a local variable's type.
    """
    return safe_post("set_local_variable_type", {"function_address": function_address, "variable_name": variable_name, "new_type": new_type})

@mcp.tool()
def get_xrefs_to(address: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references to the specified address (xref to).
    
    Args:
        address: Target address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references to the specified address
    """
    return safe_get("xrefs_to", {"address": address, "offset": offset, "limit": limit})

@mcp.tool()
def get_xrefs_from(address: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references from the specified address (xref from).
    
    Args:
        address: Source address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references from the specified address
    """
    return safe_get("xrefs_from", {"address": address, "offset": offset, "limit": limit})

@mcp.tool()
def get_function_xrefs(name: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references to the specified function by name.
    
    Args:
        name: Function name to search for
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references to the specified function
    """
    return safe_get("function_xrefs", {"name": name, "offset": offset, "limit": limit})

@mcp.tool()
def list_strings(offset: int = 0, limit: int = 2000, filter: str = None) -> list:
    """
    List all defined strings in the program with their addresses.
    
    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of strings to return (default: 2000)
        filter: Optional filter to match within string content
        
    Returns:
        List of strings with their addresses
    """
    params = {"offset": offset, "limit": limit}
    if filter:
        params["filter"] = filter
    return safe_get("strings", params)

@mcp.tool()
def create_namespace(namespace_path: str) -> str:
    """
    Create a namespace hierarchy from a :: delimited path (e.g. "jag::engine").
    Creates all intermediate namespaces as needed.
    """
    return safe_post("createNamespace", {"namespace_path": namespace_path})

@mcp.tool()
def move_symbol_to_namespace(address: str, namespace_path: str) -> str:
    """
    Move the primary symbol at a given address into a namespace.
    The namespace hierarchy is created if it doesn't exist.

    Args:
        address: Address of the symbol to move (e.g. "0x1400010a0")
        namespace_path: Target namespace path with :: delimiters (e.g. "jag::engine")
    """
    return safe_post("moveSymbolToNamespace", {"address": address, "namespace_path": namespace_path})

@mcp.tool()
def list_namespace_contents(namespace_path: str, offset: int = 0, limit: int = 100) -> list:
    """
    List the symbols contained within a namespace.

    Args:
        namespace_path: Namespace path with :: delimiters (e.g. "jag::engine")
        offset: Pagination offset (default: 0)
        limit: Maximum number of symbols to return (default: 100)

    Returns:
        List of symbols with their type and address
    """
    return safe_get("listNamespaceContents", {
        "namespace_path": namespace_path,
        "offset": offset,
        "limit": limit
    })

# ── Data Structure Tools ──────────────────────────────────────────────────

@mcp.tool()
def create_struct(name: str, size: int, category_path: str = "/") -> str:
    """
    Create a new structure (struct) data type in the program's Data Type Manager.

    Structures are the fundamental building block for reverse engineering complex
    data layouts. Use this to define C-style structs that represent objects, packets,
    file headers, or any contiguous memory layout with typed fields at fixed offsets.

    Call criteria:
    - When you identify a memory region accessed with consistent field offsets in
      decompiled code (e.g., repeated ptr+0x0, ptr+0x8, ptr+0x10 patterns)
    - When reconstructing object layouts, vtable structures, or protocol headers
    - Before using add_struct_field to populate the struct with typed fields
    - When importing known struct definitions from documentation or header files

    Args:
        name: Name for the new structure (e.g., "PacketHeader", "VTableEntry").
              Must be unique within the given category path.
        size: Total size of the structure in bytes. Fields placed with
              add_struct_field must fit within this size. Use the largest offset
              plus field size you've observed in decompiled code.
        category_path: Category path in the Data Type Manager tree (default: "/").
                       Use forward-slash-separated paths like "/MyProject/Networking"
                       to organize types into folders.

    Returns:
        Success message confirming creation with name and size, or an error message.
    """
    return safe_post("createStruct", {"name": name, "size": str(size), "category_path": category_path})


@mcp.tool()
def add_struct_field(struct_name: str, offset: int, field_type: str, field_name: str,
                     field_length: int = 0, comment: str = "") -> str:
    """
    Add or replace a field at a specific byte offset within an existing structure.

    This is the key tool for structure reconstruction in reverse engineering. It places
    a typed field at an exact byte offset, which is essential when you know from
    disassembly that "at offset 0x10 there's a pointer" or "at offset 0x0 there's
    a vtable pointer."

    Call criteria:
    - After creating a struct with create_struct, use this to define its fields
    - When you observe memory accesses at specific offsets in decompiled code
      (e.g., *(int*)(ptr + 0x8) suggests an int field at offset 8)
    - When mapping out known structure layouts from documentation or headers
    - To correct Ghidra's auto-analysis by specifying exact field types

    Args:
        struct_name: Name of the target structure (e.g., "PacketHeader"). Must
                     already exist in the Data Type Manager.
        offset: Byte offset where the field starts (e.g., 0 for first field,
                8 for a field at byte 8, 0x10 for offset 16). Must not cause the
                field to extend beyond the struct's total size.
        field_type: The data type name for the field. Supports:
                    - Primitives: "int", "uint", "short", "char", "long", "bool", "void"
                    - Sized types: "byte", "word", "dword", "longlong", "ulonglong"
                    - Pointers: "int*", "char*", "MyStruct*" or Windows-style "PINT"
                    - Custom types: Any struct/union/enum name already in the program
        field_name: Name for the field (e.g., "vtable", "refCount", "pNext").
        field_length: Optional explicit length in bytes. If 0 or omitted, uses the
                      natural size of field_type.
        comment: Optional comment describing the field's purpose.

    Returns:
        Success message confirming the field was placed, or an error message.
    """
    return safe_post("addStructField", {
        "struct_name": struct_name,
        "offset": str(offset),
        "field_type": field_type,
        "field_name": field_name,
        "field_length": str(field_length),
        "comment": comment
    })


@mcp.tool()
def delete_struct_field(struct_name: str, offset: int) -> str:
    """
    Clear (delete) the field at a specific byte offset within a structure.

    Removes the typed field definition at the given offset, reverting those bytes
    back to undefined. The structure's total size is not changed; only the field
    definition at that offset is removed.

    Call criteria:
    - When a previously defined field turns out to be incorrect after further analysis
    - When restructuring a struct layout and needing to clear fields before
      redefining them with different types or sizes
    - When cleaning up auto-analysis artifacts in a structure

    Args:
        struct_name: Name of the target structure (e.g., "PacketHeader"). Must
                     already exist in the Data Type Manager.
        offset: Byte offset of the field to clear. Must correspond to the start
                offset of an existing defined field.

    Returns:
        Success message confirming the field was cleared, or an error message.
    """
    return safe_post("deleteStructField", {
        "struct_name": struct_name,
        "offset": str(offset)
    })


@mcp.tool()
def get_struct_fields(struct_name: str, offset: int = 0, limit: int = 100) -> list:
    """
    List all defined fields of a structure with their offsets, types, and sizes.

    Returns detailed information about each field in the structure, which is
    essential for understanding memory layouts, verifying struct definitions,
    and planning further field additions.

    Call criteria:
    - After creating and populating a struct, to verify the layout is correct
    - When examining an existing struct to understand its memory layout
    - Before adding new fields, to see which offsets are already defined
    - When comparing a struct definition against observed memory access patterns

    Args:
        struct_name: Name of the structure to inspect (e.g., "PacketHeader").
                     Must already exist in the Data Type Manager.
        offset: Pagination offset for the field list (default: 0).
        limit: Maximum number of fields to return (default: 100).

    Returns:
        List of field descriptions, each formatted as:
        "Offset: N, Type: TypeName, Name: FieldName, Length: N, Comment: text"
    """
    return safe_get("getStructFields", {
        "struct_name": struct_name,
        "offset": offset,
        "limit": limit
    })


@mcp.tool()
def create_union(name: str, category_path: str = "/") -> str:
    """
    Create a new union data type in the program's Data Type Manager.

    Unions define overlapping fields that share the same memory region. The union's
    total size equals the size of its largest member. Use this for C-style unions
    where different interpretations of the same bytes are needed.

    Call criteria:
    - When decompiled code shows the same memory location being accessed with
      different types (e.g., cast as int in one path, float in another)
    - When reversing tagged unions or variant types (combine with an enum for the tag)
    - When a field in a struct can hold different types depending on context
    - When modeling hardware registers with multiple access widths

    Args:
        name: Name for the new union (e.g., "ValueUnion", "RegisterOverlay").
              Must be unique within the given category path.
        category_path: Category path in the Data Type Manager tree (default: "/").
                       Use forward-slash-separated paths like "/MyProject/Types".

    Returns:
        Success message confirming creation, or an error message.
    """
    return safe_post("createUnion", {"name": name, "category_path": category_path})


@mcp.tool()
def add_union_field(union_name: str, field_type: str, field_name: str,
                    field_length: int = 0, comment: str = "") -> str:
    """
    Add a new field (member) to an existing union data type.

    Each field added to a union overlaps with all other fields starting at offset 0.
    The union automatically grows to accommodate the largest member.

    Call criteria:
    - After creating a union with create_union, use this to add its members
    - When defining alternative interpretations of the same memory region
    - When modeling variant types with different possible representations

    Args:
        union_name: Name of the target union (e.g., "ValueUnion"). Must already
                    exist in the Data Type Manager.
        field_type: The data type name for the field. Supports the same types as
                    add_struct_field: primitives, sized types, pointers, and
                    custom types.
        field_name: Name for the field (e.g., "asInt", "asFloat", "asPointer").
        field_length: Optional explicit length in bytes. If 0 or omitted, uses the
                      natural size of field_type.
        comment: Optional comment describing when this interpretation applies.

    Returns:
        Success message confirming the field was added, or an error message.
    """
    return safe_post("addUnionField", {
        "union_name": union_name,
        "field_type": field_type,
        "field_name": field_name,
        "field_length": str(field_length),
        "comment": comment
    })


@mcp.tool()
def create_enum(name: str, size: int = 4, category_path: str = "/") -> str:
    """
    Create a new enumeration (enum) data type in the program's Data Type Manager.

    Enums map symbolic names to integer values, making decompiled code far more
    readable. Use this to replace magic numbers with meaningful constants.

    Call criteria:
    - When decompiled code uses magic number constants that represent states,
      flags, opcodes, error codes, or command types
    - When reversing protocol parsers that switch on integer command/message IDs
    - When you identify a set of related constants used in comparisons or switch
      statements
    - Before using add_enum_value to populate the enum with named constants

    Args:
        name: Name for the new enum (e.g., "MessageType", "ErrorCode", "Flags").
              Must be unique within the given category path.
        size: Storage size in bytes. Must be 1, 2, 4, or 8. Determines the range
              of values the enum can hold: 1 byte = 0-255, 2 bytes = 0-65535,
              4 bytes (default) = 0-4294967295, 8 bytes = full 64-bit range.
        category_path: Category path in the Data Type Manager tree (default: "/").
                       Use forward-slash-separated paths like "/MyProject/Enums".

    Returns:
        Success message confirming creation with name and size, or an error message.
    """
    return safe_post("createEnum", {"name": name, "size": str(size), "category_path": category_path})


@mcp.tool()
def add_enum_value(enum_name: str, entry_name: str, value: int) -> str:
    """
    Add a named constant value to an existing enumeration data type.

    This associates a symbolic name with a numeric value in the enum, so that when
    the value appears in decompiled code, Ghidra can display the meaningful name
    instead of a raw number.

    Call criteria:
    - After creating an enum with create_enum, use this to populate it with values
    - When you identify what specific magic numbers mean from context, documentation,
      or reverse engineering (e.g., 0x01 = MSG_CONNECT, 0x02 = MSG_DISCONNECT)
    - When building up a flags enum where each bit has a name
    - When mapping error codes, opcodes, or status values to symbolic names

    Args:
        enum_name: Name of the target enum (e.g., "MessageType"). Must already
                   exist in the Data Type Manager.
        entry_name: Symbolic name for the value (e.g., "MSG_CONNECT", "ERR_TIMEOUT").
                    Must be unique within the enum.
        value: Integer value to associate with the name. Supports negative values
               and values up to the enum's size limit. For hex values, pass the
               integer equivalent (e.g., 255 for 0xFF).

    Returns:
        Success message confirming the value was added, or an error message.
    """
    return safe_post("addEnumValue", {
        "enum_name": enum_name,
        "entry_name": entry_name,
        "value": str(value)
    })


@mcp.tool()
def get_data_type(name: str) -> str:
    """
    Get detailed information about any data type by name, including its fields or values.

    This is the primary inspection tool for data types. It returns comprehensive
    information adapted to the type's kind: structure fields with offsets, union
    members with ordinals, enum name-value pairs, or basic type metadata.

    Call criteria:
    - To examine the layout of a structure, union, or enum before modifying it
    - To verify that a data type was created correctly after using create_struct,
      create_union, or create_enum
    - To understand existing data types in the program (including auto-analyzed ones)
    - When you need to know a type's size, category, or field details before
      applying it to an address or using it in another type

    Args:
        name: The data type name to look up (e.g., "GUID", "HANDLE", "MyStruct").
              Searches all categories in the Data Type Manager, so you don't need
              to specify the full path. Case-insensitive fallback is used if an
              exact match is not found.

    Returns:
        Multi-line text with type details. Format depends on the type kind:
        - Structure: name, category, length, alignment, then each field with
          offset, type, name, length, and comment
        - Union: name, category, length, then each field with ordinal, type,
          name, length, and comment
        - Enum: name, category, length, then each value with name and numeric value
        - Other: name, category, length, class name, and description
    """
    return "\n".join(safe_get("getDataType", {"name": name}))


@mcp.tool()
def apply_struct_to_address(address: str, struct_name: str) -> str:
    """
    Apply a structure data type at a specific memory address in the program listing.

    This overlays the structure definition onto raw bytes at the given address,
    replacing any existing code units. After applying, the Listing view will show
    the structured data with named fields instead of raw bytes or undefined data.

    Call criteria:
    - After defining a struct and its fields, apply it where instances of that
      struct exist in the binary's data sections
    - When you've identified a global variable, heap allocation, or stack region
      that matches a struct layout
    - To label known data structures at fixed addresses (e.g., PE headers, ELF
      sections, configuration blocks)
    - When Ghidra shows undefined bytes that you've determined match a known struct

    Args:
        address: The memory address where the struct instance starts, in hex format
                 (e.g., "0x00401000", "0x140005000"). The address must be valid and
                 there must be enough bytes from this address to cover the struct's
                 full size.
        struct_name: Name of the structure to apply (e.g., "PacketHeader"). Must
                     already exist in the Data Type Manager.

    Returns:
        Success message confirming the struct was applied at the address, or an
        error message if the struct was not found, the address is invalid, or
        there was a conflict.
    """
    return safe_post("applyStructToAddress", {
        "address": address,
        "struct_name": struct_name
    })


# ── Signature Refactoring Tools ────────────────────────────────────────────

@mcp.tool()
def get_function_signature(address: str) -> str:
    """
    Retrieve the full signature details of a function at the specified address.

    Returns a multi-line breakdown of the function's prototype, return type,
    calling convention, parameter count, and each parameter's type, name,
    ordinal, and storage location. This is the primary tool for inspecting
    a function's current signature before making targeted modifications.

    Call criteria:
    - Before renaming, retyping, or adding/removing parameters -- use this
      to see the current state of the signature and parameter indices
    - When decompiled output looks wrong and you want to inspect what Ghidra
      currently believes the function signature to be
    - To verify the result after using set_return_type, add_parameter,
      remove_parameter, change_parameter_type, or rename_parameter
    - When you need parameter ordinal or storage info to understand calling
      convention behavior (e.g., which params are in registers vs. stack)

    Args:
        address: Address of the function entry point in hex format
                 (e.g., "0x1400010a0", "00401000"). Must point to the
                 start of a defined function.

    Returns:
        Multi-line text containing:
        - Prototype: the full C-style function signature
        - Return Type: the function's return type name
        - Calling Convention: e.g., __stdcall, __cdecl, __fastcall, default
        - Parameter Count: number of parameters
        - One line per parameter with type, name, ordinal, and storage
    """
    return "\n".join(safe_get("getFunctionSignature", {"address": address}))


@mcp.tool()
def set_return_type(function_address: str, return_type: str) -> str:
    """
    Change the return type of a function at the specified address.

    This tool allows precise control over a function's return type without
    modifying the rest of its signature. Use this instead of set_function_prototype
    when you only need to change what the function returns.

    Call criteria:
    - When decompiled output shows incorrect return type (e.g., Ghidra inferred
      "undefined" but you know it returns a pointer to a struct)
    - After creating a new struct/type that a function should return
    - When fixing calling convention mismatches that cause wrong return types
    - When the function clearly returns a specific type based on how callers
      use the return value

    Args:
        function_address: Address of the function in hex format (e.g., "0x1400010a0").
                         Must point to the entry point of an existing function.
        return_type: The new return type name. Supports:
                     - Primitives: "int", "void", "char", "bool", "long"
                     - Sized types: "byte", "word", "dword", "longlong"
                     - Pointers: "int*", "void*", "MyStruct*"
                     - Custom types: Any struct/union/enum name in the program

    Returns:
        Success message confirming the return type change, or an error message
        if the function was not found or the type could not be resolved.
    """
    return safe_post("setReturnType", {"function_address": function_address, "return_type": return_type})


@mcp.tool()
def add_parameter(function_address: str, param_name: str, param_type: str, index: int = -1) -> str:
    """
    Add a new parameter to a function at the specified address.

    Inserts a parameter at a specific index or appends it to the end of the
    parameter list. The parameter is created with USER_DEFINED source type,
    which means Ghidra will preserve it across re-analysis.

    Call criteria:
    - When you discover a function takes more arguments than Ghidra detected
      (common with optimized code or non-standard calling conventions)
    - When adding a 'this' pointer parameter to a method that Ghidra didn't
      recognize as a member function
    - When reconstructing the signature of a variadic function and adding
      known fixed parameters
    - After identifying a missing parameter from call sites or register usage

    Args:
        function_address: Address of the function in hex format (e.g., "0x1400010a0").
                         Must point to the entry point of an existing function.
        param_name: Name for the new parameter (e.g., "ctx", "buffer", "size").
                    Must be a valid C identifier.
        param_type: Data type for the parameter. Supports:
                    - Primitives: "int", "void*", "char", "bool", "long"
                    - Sized types: "byte", "word", "dword", "longlong"
                    - Pointers: "int*", "char*", "MyStruct*"
                    - Custom types: Any struct/union/enum name in the program
        index: Position to insert the parameter (0-based). Use -1 (default) to
               append at the end. Use 0 to insert before the first parameter.
               Existing parameters at and after this index shift right.

    Returns:
        Success message confirming the parameter was added, or an error message
        if the function was not found or the type could not be resolved.
    """
    return safe_post("addParameter", {
        "function_address": function_address,
        "param_name": param_name,
        "param_type": param_type,
        "index": str(index)
    })


@mcp.tool()
def remove_parameter(function_address: str, index: int) -> str:
    """
    Remove a parameter from a function by its index position.

    Deletes the parameter at the specified 0-based index. Parameters after the
    removed one shift left to fill the gap. Use get_function_signature first
    to see current parameter indices.

    Call criteria:
    - When Ghidra added a spurious parameter that doesn't actually exist
      (common with incorrect calling convention detection)
    - When simplifying a function signature after determining a parameter is
      unused or was misidentified
    - When fixing up thunk functions that inherited incorrect parameters
    - After changing calling convention, to remove parameters that are now
      handled implicitly (e.g., removing explicit 'this' after setting __thiscall)

    Args:
        function_address: Address of the function in hex format (e.g., "0x1400010a0").
                         Must point to the entry point of an existing function.
        index: 0-based index of the parameter to remove. Must be in range
               [0, parameter_count - 1]. Use get_function_signature to check
               current parameter indices before removing.

    Returns:
        Success message confirming the parameter was removed, or an error message
        if the index is out of range or the function was not found.
    """
    return safe_post("removeParameter", {
        "function_address": function_address,
        "index": str(index)
    })


@mcp.tool()
def change_parameter_type(function_address: str, index: int, new_type: str) -> str:
    """
    Change the data type of a specific parameter in a function's signature.

    Modifies only the type of the parameter at the given index, preserving its
    name and position. This is more surgical than set_function_prototype when
    you only need to fix one parameter's type.

    Call criteria:
    - When a parameter is typed as "undefined" or "int" but you know it's
      actually a pointer to a struct, string, or other specific type
    - When decompiled code shows type casts on a parameter that indicate
      the wrong type was inferred
    - When applying struct types you've created to function parameters
    - When correcting Ghidra's auto-analysis of parameter types based on
      how the parameter is used in the function body

    Args:
        function_address: Address of the function in hex format (e.g., "0x1400010a0").
                         Must point to the entry point of an existing function.
        index: 0-based index of the parameter to modify. Must be in range
               [0, parameter_count - 1]. Use get_function_signature to find
               the correct index.
        new_type: The new data type name for the parameter. Supports:
                  - Primitives: "int", "void", "char", "bool", "long"
                  - Sized types: "byte", "word", "dword", "longlong"
                  - Pointers: "int*", "char*", "void*", "MyStruct*"
                  - Custom types: Any struct/union/enum name in the program

    Returns:
        Success message confirming the type change, or an error message if the
        index is out of range, the function was not found, or the type could
        not be resolved.
    """
    return safe_post("changeParameterType", {
        "function_address": function_address,
        "index": str(index),
        "new_type": new_type
    })


@mcp.tool()
def rename_parameter(function_address: str, index: int, new_name: str) -> str:
    """
    Rename a specific parameter in a function's signature by its index.

    Changes only the name of the parameter at the given index, preserving its
    type, position, and storage. Parameter names appear in decompiled output
    and greatly improve code readability.

    Call criteria:
    - When decompiled output shows auto-generated parameter names like
      "param_1", "param_2" that you can give meaningful names based on
      how they are used in the function body
    - When reversing a function whose parameter names are known from
      documentation, debug symbols, or calling conventions
    - After adding a parameter with add_parameter, to fix its name if needed
    - When cleaning up function signatures for documentation or reporting

    Args:
        function_address: Address of the function in hex format (e.g., "0x1400010a0").
                         Must point to the entry point of an existing function.
        index: 0-based index of the parameter to rename. Must be in range
               [0, parameter_count - 1]. Use get_function_signature to find
               the correct index.
        new_name: New name for the parameter (e.g., "buffer", "length", "flags").
                  Must be a valid C identifier. Should be descriptive of the
                  parameter's purpose.

    Returns:
        Success message confirming the rename, or an error message if the
        index is out of range or the function was not found.
    """
    return safe_post("renameParameter", {
        "function_address": function_address,
        "index": str(index),
        "new_name": new_name
    })


@mcp.tool()
def set_calling_convention(function_address: str, calling_convention: str) -> str:
    """
    Set the calling convention of a function at the specified address.

    The calling convention determines how parameters are passed (registers vs.
    stack), who cleans up the stack, and how the return value is delivered.
    Changing it affects parameter storage assignments and the decompiled output.

    Call criteria:
    - When Ghidra misidentified the calling convention (e.g., a __thiscall
      method was detected as __cdecl, causing the first parameter to be wrong)
    - When reversing Windows COM/OLE code that uses __stdcall
    - When a function uses __fastcall but Ghidra defaulted to __cdecl
    - When fixing x86 C++ methods that need __thiscall to correctly identify
      the 'this' pointer in ECX
    - After importing type information that specifies a particular convention

    Args:
        function_address: Address of the function in hex format (e.g., "0x1400010a0").
                         Must point to the entry point of an existing function.
        calling_convention: The calling convention name. Common values:
                           - "default" - use the program's default convention
                           - "__cdecl" - C declaration (caller cleans stack)
                           - "__stdcall" - Standard call (callee cleans stack)
                           - "__fastcall" - First 2 params in ECX/EDX (x86)
                           - "__thiscall" - C++ method (this in ECX on x86)
                           - "__vectorcall" - SIMD-optimized parameter passing
                           The available conventions depend on the program's
                           architecture and compiler specification.

    Returns:
        Success message confirming the convention change, or an error message
        if the function was not found or the convention name is invalid.
    """
    return safe_post("setCallingConvention", {
        "function_address": function_address,
        "calling_convention": calling_convention
    })


def main():
    parser = argparse.ArgumentParser(description="MCP server for Ghidra")
    parser.add_argument("--ghidra-server", type=str, default=DEFAULT_GHIDRA_SERVER,
                        help=f"Ghidra server URL, default: {DEFAULT_GHIDRA_SERVER}")
    parser.add_argument("--mcp-host", type=str, default="127.0.0.1",
                        help="Host to run MCP server on (only used for sse), default: 127.0.0.1")
    parser.add_argument("--mcp-port", type=int,
                        help="Port to run MCP server on (only used for sse), default: 8081")
    parser.add_argument("--transport", type=str, default="stdio", choices=["stdio", "sse"],
                        help="Transport protocol for MCP, default: stdio")
    args = parser.parse_args()
    
    # Use the global variable to ensure it's properly updated
    global ghidra_server_url
    if args.ghidra_server:
        ghidra_server_url = args.ghidra_server
    
    if args.transport == "sse":
        try:
            # Set up logging
            log_level = logging.INFO
            logging.basicConfig(level=log_level)
            logging.getLogger().setLevel(log_level)

            # Configure MCP settings
            mcp.settings.log_level = "INFO"
            if args.mcp_host:
                mcp.settings.host = args.mcp_host
            else:
                mcp.settings.host = "127.0.0.1"

            if args.mcp_port:
                mcp.settings.port = args.mcp_port
            else:
                mcp.settings.port = 8081

            logger.info(f"Connecting to Ghidra server at {ghidra_server_url}")
            logger.info(f"Starting MCP server on http://{mcp.settings.host}:{mcp.settings.port}/sse")
            logger.info(f"Using transport: {args.transport}")

            mcp.run(transport="sse")
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
    else:
        mcp.run()
        
if __name__ == "__main__":
    main()

