import json
import os
import sys
from ghidra.program.model.listing import FunctionIterator
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.block import BasicBlockModel
from ghidra.program.model.block import SimpleBlockModel
from ghidra.program.model.pcode import PcodeOp


try:
    output_dir = os.environ.get('GHIDRA_EXPORT_DIR', '.')
except Exception as e:
    print(f"Error getting output directory from environment: {e}")
    print("Usage: Set GHIDRA_EXPORT_DIR environment variable")
    sys.exit(1)


if not output_dir:
    print("Error: No output directory specified")
    sys.exit(1)

if not os.path.exists(output_dir):
    try:
        os.makedirs(output_dir)
    except Exception as e:
        print(f"Error creating output directory {output_dir}: {e}")
        sys.exit(1)

print(f"Exporting analysis results to: {output_dir}")


pseudocode_dir = os.path.join(output_dir, "pseudocode")
if not os.path.exists(pseudocode_dir):
    try:
        os.makedirs(pseudocode_dir)
    except Exception as e:
        print(f"Error creating pseudocode directory {pseudocode_dir}: {e}")
        pseudocode_dir = None

program = getCurrentProgram()
monitor = monitor
listing = program.getListing()
symbol_table = program.getSymbolTable()


decompiler_interface = None
try:
    tool = state.getTool()
    if tool:
        decompiler_service = tool.getService(None)
        if decompiler_service:
            decompiler_interface = decompiler_service.getDecompilerInterface(program, monitor)
except:
    pass

functions = []
function_manager = program.getFunctionManager()

for func in function_manager.getFunctions(True):
    try:
        func_data = {
            "name": func.getName(),
            "addr": hex(func.getEntryPoint().getOffset()),
            "size": func.getBody().getNumAddresses(),
            "parameters": [],
            "return_type": str(func.getReturnType()),
            "calling_convention": func.getCallingConventionName(),
            "is_thunk": func.isThunk(),
            "is_external": func.isExternal(),
            "has_body": func.getBody() is not None
        }
        
      
        for param in func.getParameters():
            param_data = {
                "name": param.getName(),
                "type": str(param.getDataType()),
                "ordinal": param.getOrdinal()
            }
            func_data["parameters"].append(param_data)
        
       
        try:
            if decompiler_interface:
                decompiled = decompiler_interface.decompileFunction(func, 30, monitor)
                if decompiled:
                    func_data["decompiled_excerpt"] = decompiled.getDecompiledFunction().getC()[:500]
            else:
                func_data["decompiled_excerpt"] = ""
        except:
            func_data["decompiled_excerpt"] = ""
        
        functions.append(func_data)
    except Exception as e:
        print(f"Error processing function {func.getName()}: {e}")


functions_file = os.path.join(output_dir, "functions.json")
with open(functions_file, 'w') as f:
    json.dump({"functions": functions}, f, indent=2)

print(f"Exported {len(functions)} functions to {functions_file}")


xrefs = {}
for func in function_manager.getFunctions(True):
    try:
        func_addr = hex(func.getEntryPoint().getOffset())
        callers = []
        callees = []
        
     
        ref_manager = program.getReferenceManager()
        refs = ref_manager.getReferencesTo(func.getEntryPoint())
        for ref in refs:
            from_addr = ref.getFromAddress()
            from_func = function_manager.getFunctionContaining(from_addr)
            if from_func:
                callers.append({
                    "addr": hex(from_addr.getOffset()),
                    "function": from_func.getName()
                })
        
     
        if func.getBody() is not None:
            func_body = func.getBody()
            instr_iter = listing.getInstructions(func_body, True)
            for instr in instr_iter:
                flow_type = instr.getFlowType()
                if flow_type.isCall():
                    call_refs = instr.getReferencesFrom()
                    for ref in call_refs:
                        to_addr = ref.getToAddress()
                        to_func = function_manager.getFunctionContaining(to_addr)
                        if to_func:
                            callees.append({
                                "addr": hex(to_addr.getOffset()),
                                "function": to_func.getName()
                            })
        
        if callers or callees:
            xrefs[func_addr] = {
                "callers": callers,
                "callees": callees
            }
    except Exception as e:
        print(f"Error processing xrefs for {func.getName()}: {e}")

xrefs_file = os.path.join(output_dir, "xrefs.json")
with open(xrefs_file, 'w') as f:
    json.dump(xrefs, f, indent=2)

print(f"Exported cross-references to {xrefs_file}")


imports = []
try:
    import_manager = program.getImportManager()
    for import_table in import_manager.getImportTables():
        for import_data in import_table.getImports():
            try:
                imports.append({
                    "name": import_data.getName(),
                    "library": import_data.getLibraryName(),
                    "addr": hex(import_data.getAddress().getOffset()) if import_data.getAddress() else None
                })
            except:
                pass
except AttributeError:
    # getImportManager not available in this Ghidra version
    # Try alternative method using symbol table
    for symbol in symbol_table.getSymbols(True):
        try:
            if symbol.getSource() == SourceType.IMPORTED:
                imports.append({
                    "name": symbol.getName(),
                    "library": "unknown",
                    "addr": hex(symbol.getAddress().getOffset()) if symbol.getAddress() else None
                })
        except:
            pass

imports_file = os.path.join(output_dir, "imports.json")
with open(imports_file, 'w') as f:
    json.dump(imports, f, indent=2)

print(f"Exported {len(imports)} imports to {imports_file}")

strings = []
try:
    string_manager = program.getStringManager()
    for string in string_manager.getStrings():
        try:
            strings.append({
                "value": string.getStringValue(),
                "addr": hex(string.getAddress().getOffset()),
                "length": string.getLength(),
                "encoding": str(string.getStringType())
            })
        except:
            pass
except AttributeError:
    # getStringManager not available in this Ghidra version
    # Try alternative method using listing.getDefinedStrings()
    try:
        defined_strings = listing.getDefinedStrings()
        for string in defined_strings:
            try:
                strings.append({
                    "value": string.getStringValue(),
                    "addr": hex(string.getAddress().getOffset()),
                    "length": string.getLength(),
                    "encoding": str(string.getStringType())
                })
            except:
                pass
    except:
        # If that fails, try searching for string data items
        try:
            data_manager = program.getListing()
            data_iter = data_manager.getDefinedData(True)
            for data in data_iter:
                try:
                    if data.isString():
                        string_value = data.getValue()
                        if string_value:
                            strings.append({
                                "value": str(string_value),
                                "addr": hex(data.getAddress().getOffset()),
                                "length": data.getLength(),
                                "encoding": str(data.getDataType())
                            })
                except:
                    pass
        except:
            pass


strings_file = os.path.join(output_dir, "strings.json")
with open(strings_file, 'w') as f:
    json.dump(strings, f, indent=2)

print(f"Exported {len(strings)} strings to {strings_file}")


for func in function_manager.getFunctions(True):
    if func.getBody() is not None and not func.isExternal():
        try:
            if decompiler_interface:
                decompiled = decompiler_interface.decompileFunction(func, 30, monitor)
                if decompiled:
                    func_addr = hex(func.getEntryPoint().getOffset())
                    if pseudocode_dir:
                        decompile_file = os.path.join(pseudocode_dir, f"{func_addr}.c")
                    else:
                        decompile_file = os.path.join(output_dir, f"decompile_{func_addr}.c")
                    with open(decompile_file, 'w') as f:
                        f.write(decompiled.getDecompiledFunction().getC())
                    print(f"Decompiled {func.getName()} to {decompile_file}")
        except Exception as e:
            print(f"Error decompiling {func.getName()}: {e}")

print("Analysis export complete!")
