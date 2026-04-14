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


flat_api = None
try:
    from ghidra.program.flatapi import FlatProgramAPI
    flat_api = FlatProgramAPI(program)
    print("Successfully initialized FlatProgramAPI")
except Exception as e:
    print(f"Warning: Could not initialize FlatProgramAPI: {e}")


try:
    from ghidra.program.model.listing import Program
    analysis_props = program.getOptions(Program.ANALYSIS_PROPERTIES)
    analysis_props.setBoolean("Non-Returning Functions - Discovered", True)
    analysis_props.setBoolean("Non-Returning Functions - Validated", True)
    print("Analysis properties configured")
except Exception as e:
    print(f"Warning: Could not configure analysis properties: {e}")


try:
    from ghidra.program.model.listing import Program
    program_info = program.getOptions(Program.PROGRAM_INFO)
    program_info.setString("Analysis Tool", "PyGhidra Enhanced")
    program_info.setString("Analysis Date", str(java.util.Date()))
    print("Program info configured")
except Exception as e:
    print(f"Warning: Could not configure program info: {e}")


decompiler_api = None
try:
    
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.app.decompiler.flatapi import FlatDecompilerAPI
    
    flat_api = FlatProgramAPI(program)
    decompiler_api = FlatDecompilerAPI(flat_api)
    print("Successfully obtained decompiler API using FlatDecompilerAPI")
except Exception as e:
    print(f"Error creating FlatDecompilerAPI: {e}")
   
    try:
        from ghidra.app.decompiler import DecompInterface
        decompiler_interface = DecompInterface()
        decompiler_interface.openProgram(program)
        decompiler_api = decompiler_interface
        print("Successfully obtained decompiler interface using DecompInterface")
    except Exception as e2:
        print(f"Error creating DecompInterface: {e2}")
        try:
            tool = state.getTool()
            if tool:
                decompiler_service = tool.getService("Decompiler")
                if decompiler_service:
                    decompiler_interface = decompiler_service.getDecompilerInterface(program, monitor)
                    decompiler_api = decompiler_interface
                    print("Successfully obtained decompiler interface via tool service")
                else:
                    print("Warning: Decompiler service not found")
            else:
                print("Warning: Tool not found")
        except Exception as e3:
            print(f"Error getting decompiler interface via tool: {e3}")

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
        
      
        if flat_api:
            try:
                func_addr = func.getEntryPoint()
            
                try:
                    func_body = func.getBody()
                    func_data["body_size"] = func_body.getNumAddresses()
                    func_data["body_start"] = hex(func_body.getMinAddress().getOffset())
                    func_data["body_end"] = hex(func_body.getMaxAddress().getOffset())
                except:
                    pass
                
              
                try:
                    callers = func.getCallingFunctions(monitor)
                    func_data["caller_count"] = len(list(callers))
                except:
                    func_data["caller_count"] = 0
                    
               
                try:
                    called = func.getCalledFunctions(monitor)
                    func_data["called_count"] = len(list(called))
                except:
                    func_data["called_count"] = 0
                    
            except Exception as e:
                print(f"Warning: Could not get enhanced metadata for {func.getName()}: {e}")
        
      
        for param in func.getParameters():
            param_data = {
                "name": param.getName(),
                "type": str(param.getDataType()),
                "ordinal": param.getOrdinal()
            }
            func_data["parameters"].append(param_data)
        
       
        try:
            if decompiler_api:

                try:
       
                    decompiled = decompiler_api.decompile(func)
                    if decompiled:
                        func_data["decompiled_excerpt"] = decompiled.getC()[:500]
                except AttributeError:
                
                    try:
                        decompiled = decompiler_api.decompileFunction(func, 30, monitor)
                        if decompiled:
                            func_data["decompiled_excerpt"] = decompiled.getDecompiledFunction().getC()[:500]
                    except AttributeError:
                    
                        try:
                            decompiled_results = decompiler_api.decompileFunction(func.getEntryPoint(), 30)
                            if decompiled_results and decompiled_results.getDecompiledFunction():
                                func_data["decompiled_excerpt"] = decompiled_results.getDecompiledFunction().getC()[:500]
                        except:
                            func_data["decompiled_excerpt"] = ""
            else:
                func_data["decompiled_excerpt"] = ""
        except Exception as e:
            print(f"Error decompiling function {func.getName()}: {e}")
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


try:
    from ghidra.program.database import ProgramDB
    
    tx_id = program.startTransaction("Export Analysis Results")
    try:
        from ghidra.program.model.listing import Program
        program_info = program.getOptions(Program.PROGRAM_INFO)
        program_info.setString("Export Status", "Completed")
        program_info.setString("Export Timestamp", str(Date()))
        
        program.endTransaction(tx_id)
        print("Program changes saved using transaction support")
    except Exception as e:
        program.endTransaction(tx_id, True)  
        print(f"Warning: Transaction aborted due to error: {e}")
except Exception as e:
    print(f"Warning: Could not use transaction support: {e}")


print(f"\nStarting decompilation for {len(list(function_manager.getFunctions(True)))} functions...")
decompiled_count = 0
for func in function_manager.getFunctions(True):
    if func.getBody() is not None and not func.isExternal():
        try:
            if decompiler_api:
             
                try:
                  
                    decompiled = decompiler_api.decompile(func)
                    if decompiled:
                        func_addr_hex = hex(func.getEntryPoint().getOffset())
                        if pseudocode_dir:
                            decompile_file = os.path.join(pseudocode_dir, f"{func_addr_hex}.c")
                        else:
                            decompile_file = os.path.join(output_dir, f"decompile_{func_addr_hex}.c")
                        with open(decompile_file, 'w') as f:
                            f.write(decompiled)
                        print(f"Decompiled {func.getName()} to {decompile_file}")
                        decompiled_count += 1
                    else:
                        print(f"Decompilation returned None for {func.getName()}")
                except AttributeError:
                    
                    try:
                        decompiled = decompiler_api.decompileFunction(func, 30, monitor)
                        if decompiled:
                            func_addr_hex = hex(func.getEntryPoint().getOffset())
                            if pseudocode_dir:
                                decompile_file = os.path.join(pseudocode_dir, f"{func_addr_hex}.c")
                            else:
                                decompile_file = os.path.join(output_dir, f"decompile_{func_addr_hex}.c")
                            with open(decompile_file, 'w') as f:
                                f.write(decompiled.getDecompiledFunction().getC())
                            print(f"Decompiled {func.getName()} to {decompile_file}")
                            decompiled_count += 1
                        else:
                            print(f"Decompilation returned None for {func.getName()}")
                    except AttributeError:
                  
                        try:
                            decompiled_results = decompiler_api.decompileFunction(func.getEntryPoint(), 30)
                            if decompiled_results and decompiled_results.getDecompiledFunction():
                                func_addr_hex = hex(func.getEntryPoint().getOffset())
                                if pseudocode_dir:
                                    decompile_file = os.path.join(pseudocode_dir, f"{func_addr_hex}.c")
                                else:
                                    decompile_file = os.path.join(output_dir, f"decompile_{func_addr_hex}.c")
                                with open(decompile_file, 'w') as f:
                                    f.write(decompiled_results.getDecompiledFunction().getC())
                                print(f"Decompiled {func.getName()} to {decompile_file}")
                                decompiled_count += 1
                            else:
                                print(f"Decompilation returned None for {func.getName()}")
                        except Exception as e:
                            print(f"Error decompiling {func.getName()} (alternative method): {e}")
            else:
                print(f"Skipping {func.getName()}: decompiler interface not available")
        except Exception as e:
            print(f"Error decompiling {func.getName()}: {e}")

print(f"Decompilation complete: {decompiled_count} functions decompiled")


try:
    coverage_data = {
        "total_functions": len(list(function_manager.getFunctions(True))),
        "decompiled_functions": decompiled_count,
        "decompile_coverage": round((float(decompiled_count) / max(len(list(function_manager.getFunctions(True))), 1)) * 100, 2)
    }
  
    try:
        memory_blocks = program.getMemory()
        total_bytes = 0
        for block in memory_blocks:
          
            try:
                start_addr = block.getStart()
                end_addr = block.getEnd()
            except:
                try:
                    start_addr = block.getMinAddress()
                    end_addr = block.getMaxAddress()
                except:
                 
                    continue
            
           
            block_size = end_addr.subtract(start_addr)
            total_bytes += int(block_size)
        
        covered_bytes = 0
        for func in function_manager.getFunctions(True):
            if func.getBody():
                covered_bytes += func.getBody().getNumAddresses()
        
        coverage_data["address_coverage"] = round((float(covered_bytes) / max(total_bytes, 1)) * 100, 2)
        coverage_data["total_bytes"] = total_bytes
        coverage_data["covered_bytes"] = covered_bytes
    except Exception as e:
        print(f"Warning: Could not calculate address coverage: {e}")
    
    coverage_file = os.path.join(output_dir, "coverage.json")
    with open(coverage_file, 'w') as f:
        json.dump(coverage_data, f, indent=2)
    print(f"Coverage analysis saved to {coverage_file}")
except Exception as e:
    print(f"Warning: Could not perform coverage analysis: {e}")


try:
    function_graph = {
        "nodes": [],
        "edges": []
    }
    
    for func in function_manager.getFunctions(True):
        if not func.isExternal():
            node = {
                "id": func.getName(),
                "addr": hex(func.getEntryPoint().getOffset()),
                "type": "function"
            }
            function_graph["nodes"].append(node)
            
        
            try:
                called = func.getCalledFunctions(monitor)
                for called_func in called:
                    if not called_func.isExternal():
                        edge = {
                            "source": func.getName(),
                            "target": called_func.getName(),
                            "type": "calls"
                        }
                        function_graph["edges"].append(edge)
            except:
                pass
    
    graph_file = os.path.join(output_dir, "function_graph.json")
    with open(graph_file, 'w') as f:
        json.dump(function_graph, f, indent=2)
    print(f"Function graph saved to {graph_file}")
except Exception as e:
    print(f"Warning: Could not generate function graph: {e}")


try:
    memory_layout = {
        "sections": []
    }
    
    memory_blocks = program.getMemory()
    for block in memory_blocks:
        
        try:
            start_addr = block.getStart()
            end_addr = block.getEnd()
        except:
            try:
                start_addr = block.getMinAddress()
                end_addr = block.getMaxAddress()
            except:
             
                continue
        
 
        block_size = end_addr.subtract(start_addr)
        

        try:
            name = block.getName()
        except:
            name = f"block_{hex(start_addr.getOffset())}"
        

        try:
            block_type = str(block.getType())
        except:
            block_type = "unknown"
        

        try:
            read_perm = block.isRead()
        except:
            read_perm = True
        try:
            write_perm = block.isWrite()
        except:
            write_perm = False
        try:
            exec_perm = block.isExecute()
        except:
            exec_perm = False
        
        section = {
            "name": name,
            "start": hex(start_addr.getOffset()),
            "end": hex(end_addr.getOffset()),
            "size": int(block_size),
            "type": block_type,
            "permissions": {
                "read": read_perm,
                "write": write_perm,
                "execute": exec_perm
            }
        }
        memory_layout["sections"].append(section)
    
    memory_file = os.path.join(output_dir, "memory_layout.json")
    with open(memory_file, 'w') as f:
        json.dump(memory_layout, f, indent=2)
    print(f"Memory layout saved to {memory_file}")
except Exception as e:
    print(f"Warning: Could not generate memory layout: {e}")

try:
    control_flow = {
        "functions": []
    }
    
    for func in function_manager.getFunctions(True):
        if func.getBody() and not func.isExternal():
            func_flow = {
                "name": func.getName(),
                "addr": hex(func.getEntryPoint().getOffset()),
                "blocks": []
            }
            
            try:
              
                from ghidra.program.model.block import BasicBlockModel
                block_model = BasicBlockModel(program)
                
                body = func.getBody()
                for block in block_model.getCodeBlocksContaining(body, monitor):
                  
                    start_addr = block.getMinAddress()
                    end_addr = block.getMaxAddress()
                    block_size = end_addr.subtract(start_addr)
                    
                    block_data = {
                        "start": hex(start_addr.getOffset()),
                        "end": hex(end_addr.getOffset()),
                        "size": int(block_size),
                        "fallthrough": None,
                        "branches": []
                    }
                    
               
                    try:
                        ft = block.getFallThrough()
                        if ft:
                            block_data["fallthrough"] = hex(ft.getOffset())
                    except:
                        pass
                    
                  
                    try:
                        for dest in block.getDestinations(monitor):
                            block_data["branches"].append(hex(dest.getOffset()))
                    except:
                        pass
                    
                    func_flow["blocks"].append(block_data)
                    
            except Exception as e:
                print(f"Warning: Could not analyze control flow for {func.getName()}: {e}")
            
            control_flow["functions"].append(func_flow)
    
    control_flow_file = os.path.join(output_dir, "control_flow.json")
    with open(control_flow_file, 'w') as f:
        json.dump(control_flow, f, indent=2)
    print(f"Control flow saved to {control_flow_file}")
except Exception as e:
    print(f"Warning: Could not generate control flow: {e}")


try:
    import time
    from java.util import Date
    
    timeline = {
        "analysis_start": str(Date()),
        "stages": [
            {
                "stage": "initialization",
                "status": "completed",
                "timestamp": str(Date())
            },
            {
                "stage": "decompilation",
                "status": "completed",
                "functions_decompiled": decompiled_count,
                "timestamp": str(Date())
            },
            {
                "stage": "export",
                "status": "in_progress",
                "timestamp": str(Date())
            }
        ],
        "statistics": {
            "total_functions": len(list(function_manager.getFunctions(True))),
            "total_strings": len(strings),
            "memory_sections": len(list(program.getMemory()))
        }
    }
    
    timeline_file = os.path.join(output_dir, "timeline.json")
    with open(timeline_file, 'w') as f:
        json.dump(timeline, f, indent=2)
    print(f"Timeline saved to {timeline_file}")
except Exception as e:
    print(f"Warning: Could not generate timeline: {e}")

print("Analysis export complete!")
