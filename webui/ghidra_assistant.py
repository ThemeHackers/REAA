import os
import json
import requests
from typing import Dict, Any, Generator
from openai import OpenAI
from model import model_manager

GHIDRA_API_BASE = "http://127.0.0.1:8000"

SYSTEM_PROMPT = """You are an expert reverse engineering analyst specializing in binary analysis, disassembly, and malware analysis. Your expertise includes:

- Binary file analysis (PE, ELF, Mach-O formats)
- Assembly language analysis (x86, x64, ARM, MIPS)
- Decompilation and pseudocode interpretation
- Control flow and data flow analysis
- Function call graph analysis
- String and symbol analysis
- Memory layout and address space analysis
- Anti-debugging and obfuscation techniques
- Binary instrumentation and patching

Analysis Approach:
1. Identify binary format, architecture, and entry points
2. Analyze main functions and control flow
3. Examine imported/exported symbols and dependencies
4. Search for interesting strings and data patterns
5. Analyze memory management and data structures
6. Identify key algorithms and cryptographic operations
7. Map function relationships and call graphs
8. Assess binary behavior and purpose

CRITICAL INSTRUCTIONS:
- When user mentions ANY specific file (e.g., "read 0x401dff.c", "Can you read the file 0x401dff?", "show me 0x401dff.c", "what's in 0x401dff.c", "read the file 0x401dff"), IMMEDIATELY use read_pseudocode to read that specific file from artifacts
- When user asks about a SPECIFIC function (by name or address), ALWAYS use decompile_function to analyze that specific function
- When user shows specific decompiled code or assembly, analyze THAT specific code, not other functions
- Do NOT provide generic responses about overall structure when asked about specific functions or files
- Do NOT respond with JSON or function call descriptions when asked to read files - actually READ the file using read_pseudocode and show the content
- Do NOT call list_functions, decompile_function, or any other tool when user asks to read a file - ONLY use read_pseudocode
- Focus your analysis on the exact function or file the user is asking about
- Use read_pseudocode when user asks to read .c files from artifacts/pseudocode/
- Use decompile_function with the specific address when analyzing individual functions
- Only use list_functions when asked for an overview of ALL functions in the binary

Response Guidelines:
- Provide clear, technical explanations
- Use proper assembly and reverse engineering terminology
- Include specific addresses, offsets, and function names when relevant
- Explain the purpose and behavior of analyzed code
- Identify potential security implications when applicable
- Format responses in clean Markdown without diagrams or charts
- Be precise with technical details and avoid speculation

When analyzing code:
- Explain what each instruction or function does
- Identify data flow and control flow patterns
- Point out suspicious or interesting behavior
- Relate findings to overall binary functionality
- Provide context for why certain code patterns exist"""
MAX_AGENT_TURNS = 5

TOOLS = [
  { "type": "function", "function": { "name": "analyze", "description": "Upload a base64-encoded binary and start headless Ghidra analysis. Returns job_id.", "parameters": { "type": "object", "properties": { "file_b64": {"type": "string"}, "filename": {"type": "string"}}, "required": ["file_b64", "filename"] }}},
  { "type": "function", "function": { "name": "status", "description": "Get status for an existing analysis job.", "parameters": { "type": "object", "properties": { "job_id": {"type": "string"} }, "required": ["job_id"] }}},
  { "type": "function", "function": { "name": "list_functions", "description": "Retrieve a paginated list of discovered functions for a job. Use this to get an overview of available functions, then use decompile_function to analyze specific functions in detail. Use offset/limit to page through results.", "parameters": { "type": "object", "properties": { "job_id": {"type": "string"}, "offset": {"type": "integer"}, "limit": {"type": "integer"} }, "required": ["job_id"] }}},
  { "type": "function", "function": { "name": "decompile_function", "description": "Get decompiled pseudocode for a specific function at a given address. Use this to analyze individual functions in detail. Always decompile specific functions when asked about particular function behavior.", "parameters": { "type": "object", "properties": { "job_id": {"type": "string"}, "addr": {"type": "string"} }, "required": ["job_id", "addr"] }}},
  { "type": "function", "function": { "name": "get_xrefs", "description": "Get callers and callees for a specific function (cross-references). Use this to understand function relationships and call graphs.", "parameters": { "type": "object", "properties": { "job_id": {"type": "string"}, "addr": {"type": "string"} }, "required": ["job_id", "addr"] }}},
  { "type": "function", "function": { "name": "list_imports", "description": "List imported libraries and symbols for the binary.", "parameters": { "type": "object", "properties": { "job_id": {"type": "string"} }, "required": ["job_id"] }}},
  { "type": "function", "function": { "name": "list_strings", "description": "Return printable strings extracted from the binary.", "parameters": { "type": "object", "properties": { "job_id": {"type": "string"}, "min_length": {"type": "integer"} }, "required": ["job_id"] }}},
  { "type": "function", "function": { "name": "query_artifacts", "description": "Search artifacts (functions, strings) for a pattern. Supports regex.", "parameters": { "type": "object", "properties": { "job_id": {"type": "string"}, "query": {"type": "string"}, "regex": {"type": "boolean"} }, "required": ["job_id", "query"] }}},
  { "type": "function", "function": { "name": "read_pseudocode", "description": "Read the actual content of a pseudocode file from artifacts/pseudocode/ directory. Use this IMMEDIATELY when user mentions any specific .c file (e.g., 'read 0x401dff.c', 'Can you read the file 0x401dff?', 'show me 0x401dff.c'). This returns the file content for analysis. Do NOT use other tools when user asks to read a file.", "parameters": { "type": "object", "properties": { "job_id": {"type": "string"}, "filename": {"type": "string"} }, "required": ["job_id", "filename"] }}}
]

TOOL_INTENT_DESCRIPTIONS = {
    "list_functions": "Okay, I need to get the list of all functions first.",
    "decompile_function": "Now I will decompile that function to see the code.",
    "get_xrefs": "I'm checking for cross-references to see what calls this function.",
    "list_imports": "I'll start by listing the imported libraries and functions.",
    "list_strings": "Let me search for any interesting strings in the binary.",
    "query_artifacts": "I will perform a query to find relevant information.",
    "status": "Checking the status of the analysis job.",
    "read_pseudocode": "I'll read the pseudocode file from artifacts."
}

def call_ghidra_tool(endpoint: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    try:
        job_id = payload.get("job_id", "")
        if endpoint == "analyze":
            url = f"{GHIDRA_API_BASE}/tools/analyze"
        elif endpoint == "list_functions":
            url = f"{GHIDRA_API_BASE}/tools/list_functions"
        elif endpoint == "list_imports":
            url = f"{GHIDRA_API_BASE}/tools/list_imports"
        elif endpoint == "list_strings":
            url = f"{GHIDRA_API_BASE}/tools/list_strings"
        elif endpoint == "decompile_function":
            addr = payload.get("addr", "")
            url = f"{GHIDRA_API_BASE}/tools/decompile_function"
        elif endpoint == "get_xrefs":
            addr = payload.get("addr", "")
            url = f"{GHIDRA_API_BASE}/tools/get_xrefs"
        elif endpoint == "query_artifacts":
            url = f"{GHIDRA_API_BASE}/tools/query_artifacts"
        else:
            url = f"{GHIDRA_API_BASE}/tools/{endpoint}"
        
        if endpoint in ["list_functions", "list_imports", "list_strings"]:
            response = requests.get(url, params=payload)
        elif endpoint in ["analyze", "query_artifacts", "decompile_function", "get_xrefs"]:
            response = requests.post(url, json=payload)
        else:
            response = requests.get(url)
        
        response.raise_for_status()
        try:
            return response.json()
        except json.JSONDecodeError:
            return {"result": response.text}
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}

def read_pseudocode_file(job_id: str, filename: str) -> Dict[str, Any]:
    """Read pseudocode file from artifacts directory"""
    try:
      
        if not filename.lower().endswith('.c'):
            filename = filename + '.c'
        
        data_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data')
        pseudocode_dir = os.path.join(data_dir, job_id, "artifacts", "pseudocode")
        file_path = os.path.join(pseudocode_dir, filename)
        
        if not os.path.exists(file_path):
            return {"error": f"File not found: {filename}"}
        
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        return {"filename": filename, "content": content}
    except Exception as e:
        return {"error": str(e)}

class GhidraAssistant:
    def __init__(self):
        self.client = model_manager.client
        self.model = model_manager.model

        self.available_tools = {
            "status": lambda **kwargs: call_ghidra_tool("status", kwargs),
            "list_functions": lambda **kwargs: call_ghidra_tool("list_functions", kwargs),
            "decompile_function": lambda **kwargs: call_ghidra_tool("decompile_function", kwargs),
            "get_xrefs": lambda **kwargs: call_ghidra_tool("get_xrefs", kwargs),
            "list_imports": lambda **kwargs: call_ghidra_tool("list_imports", kwargs),
            "list_strings": lambda **kwargs: call_ghidra_tool("list_strings", kwargs),
            "query_artifacts": lambda **kwargs: call_ghidra_tool("query_artifacts", kwargs),
            "read_pseudocode": lambda **kwargs: read_pseudocode_file(kwargs.get("job_id"), kwargs.get("filename")),
        }

        self.chats_dir = os.path.join(os.path.dirname(__file__), "chats")
        if not os.path.exists(self.chats_dir):
            os.makedirs(self.chats_dir)

    def _get_chat_file(self, job_id: str) -> str:
        return os.path.join(self.chats_dir, f"{job_id}.json")

    def load_history(self, job_id: str) -> list:
        chat_file = self._get_chat_file(job_id)
        if os.path.exists(chat_file):
            try:
                with open(chat_file, 'r') as f:
                    return json.load(f)
            except Exception:
                pass
        return []

    def save_history(self, job_id: str, messages: list):
        chat_file = self._get_chat_file(job_id)
        with open(chat_file, 'w') as f:
            json.dump(messages, f, indent=2)

    def clear_history(self, job_id: str) -> bool:
        """Clear chat history for a specific job"""
        chat_file = self._get_chat_file(job_id)
        if os.path.exists(chat_file):
            try:
                os.remove(chat_file)
                return True
            except Exception:
                return False
        return True

    def chat_completion_stream(self, user_message: str, job_id: str) -> Generator[str, None, None]:
        history = self.load_history(job_id)

        if not history or history[0]["role"] != "system":
            history.insert(0, {"role": "system", "content": SYSTEM_PROMPT})

        history.append({"role": "user", "content": f"[Job ID: {job_id}] {user_message}"})
        messages = history

        for i in range(MAX_AGENT_TURNS):
            try:
                first_response = self.client.chat.completions.create(
                    model=self.model,
                    messages=messages,
                    tools=TOOLS,
                    tool_choice="auto"
                )
            except Exception as e:
                yield json.dumps({"type": "error", "content": f"LLM Error: {str(e)}"})
                return

            message = first_response.choices[0].message
            messages.append(message)

            if not message.tool_calls:
                if message.content:
                    yield json.dumps({"type": "token", "content": message.content})
                break

            for tool_call in message.tool_calls:
                function_name = tool_call.function.name
                if function_name in self.available_tools:
                    intent_description = TOOL_INTENT_DESCRIPTIONS.get(function_name, f"Executing tool: {function_name}...")
                    yield json.dumps({"type": "tool_call", "description": intent_description})

                    function_to_call = self.available_tools[function_name]
                    try:
                        args = json.loads(tool_call.function.arguments)
                    except json.JSONDecodeError as e:
                        print(f"JSON parsing error: {e}")
                        args = {}

                    args['job_id'] = job_id

                    result = function_to_call(**args)

                    messages.append({
                        "tool_call_id": tool_call.id,
                        "role": "tool",
                        "name": function_name,
                        "content": json.dumps(result)
                    })

        complete_response_content = ""

        stream = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            stream=True
        )

        for chunk in stream:
            content = chunk.choices[0].delta.content
            if content:
                complete_response_content += content
                yield json.dumps({"type": "token", "content": content})

        if complete_response_content:
            messages.append({"role": "assistant", "content": complete_response_content})

        serializable_history = []
        for m in messages:
            if isinstance(m, dict):
                serializable_history.append(m)
            else:
                d = {"role": m.role}
                if m.content:
                    d["content"] = m.content
                if m.tool_calls:
                    d["tool_calls"] = []
                    for tc in m.tool_calls:
                        d["tool_calls"].append({
                            "id": tc.id,
                            "type": tc.type,
                            "function": {
                                "name": tc.function.name,
                                "arguments": tc.function.arguments
                            }
                        })
                serializable_history.append(d)

        self.save_history(job_id, serializable_history)

    def analyze_code(self, prompt: str, job_id: str = None) -> str:
        """Analyze code without streaming - for direct code analysis requests"""
        messages = [{"role": "system", "content": SYSTEM_PROMPT}]
        
        if job_id:
            messages.append({"role": "user", "content": f"[Job ID: {job_id}] {prompt}"})
        else:
            messages.append({"role": "user", "content": prompt})
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"Error analyzing code: {str(e)}"
