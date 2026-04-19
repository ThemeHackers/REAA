import os
import json
import requests
import re
from typing import Dict, Any, Generator, List
from openai import OpenAI
from rich.console import Console

console = Console()

from model import model_manager

GHIDRA_API_BASE = "http://127.0.0.1:8000"

SECURITY_SYSTEM_PROMPT = """
You are an expert cybersecurity researcher and vulnerability analyst specializing in binary reverse engineering and security analysis. Your expertise includes:

- Binary reverse engineering and disassembly analysis
- Memory corruption vulnerabilities (buffer overflows, heap overflows, use-after-free, double-free)
- Code injection and ROP chain analysis
- Authentication and authorization bypasses
- Privilege escalation and sandbox escape techniques
- Cryptographic implementation weaknesses
- Race conditions and TOCTOU vulnerabilities
- Format string and integer overflow vulnerabilities
- Anti-debugging and anti-analysis techniques
- Binary instrumentation and exploitation techniques

Reverse Engineering Analysis Approach:
1. Identify binary format (PE, ELF, Mach-O), architecture, and protection mechanisms
2. Analyze entry points, main functions, and control flow graphs
3. Examine dangerous API calls and security-sensitive patterns
4. Review memory management practices (malloc/free, new/delete, stack usage)
5. Validate input validation and sanitization mechanisms
6. Assess privilege escalation paths and permission checks
7. Identify attack surfaces and exposed interfaces
8. Analyze string operations and buffer handling
9. Examine cryptographic implementations and random number generation
10. Map data flow and identify taint sources/sinks

Security Assessment Guidelines:
- Provide CVSS scoring when applicable (Base Score, Impact, Exploitability)
- Assess exploitability and impact severity
- Identify proof-of-concept exploitation scenarios
- Suggest specific mitigation strategies and code fixes
- Reference similar CVEs and known attack patterns
- Consider both local and remote attack vectors
- Evaluate defense-in-depth measures

Response Format:
- Executive Summary (concise overview)
- Technical Findings (with specific addresses and function names)
- Risk Assessment (Critical/High/Medium/Low with justification)
- Exploitation Scenarios (step-by-step attack vectors)
- Mitigation Recommendations (specific actionable fixes)
- Security Best Practices for similar code patterns

IMPORTANT: Format responses in clean Markdown without diagrams, charts, or visual elements. Focus on technical precision and actionable security insights."""

SECURITY_TOOLS = [
    {
        "type": "function", 
        "function": {
            "name": "analyze_binary_security", 
            "description": "Comprehensive security analysis of binary file",
            "parameters": {
                "type": "object", 
                "properties": {
                    "job_id": {"type": "string"},
                    "file_type": {
                        "type": "string", 
                        "enum": ["exe", "dll", "sys", "driver", "unknown"]
                    },
                    "analysis_depth": {
                        "type": "string", 
                        "enum": ["quick", "standard", "deep"],
                        "default": "standard"
                    }
                },
                "required": ["job_id"]
            }
        }
    },
    {
        "type": "function", 
        "function": {
            "name": "detect_memory_corruption", 
            "description": "Detect memory corruption vulnerabilities",
            "parameters": {
                "type": "object", 
                "properties": {
                    "job_id": {"type": "string"},
                    "check_types": {
                        "type": "array", 
                        "items": {"type": "string"},
                        "enum": ["buffer_overflow", "heap_overflow", "use_after_free", "double_free", "null_pointer"]
                    }
                },
                "required": ["job_id"]
            }
        }
    },
    {
        "type": "function", 
        "function": {
            "name": "scan_dangerous_apis", 
            "description": "Scan for dangerous API usage patterns",
            "parameters": {
                "type": "object", 
                "properties": {
                    "job_id": {"type": "string"},
                    "api_categories": {
                        "type": "array", 
                        "items": {"type": "string"},
                        "enum": ["memory", "string", "file", "network", "crypto", "process"]
                    }
                },
                "required": ["job_id"]
            }
        }
    },
    {
        "type": "function", 
        "function": {
            "name": "analyze_control_flow", 
            "description": "Analyze control flow for potential vulnerabilities",
            "parameters": {
                "type": "object", 
                "properties": {
                    "job_id": {"type": "string"},
                    "function_addr": {"type": "string"}
                },
                "required": ["job_id"]
            }
        }
    },
    {
        "type": "function", 
        "function": {
            "name": "check_input_validation", 
            "description": "Check input validation mechanisms",
            "parameters": {
                "type": "object", 
                "properties": {
                    "job_id": {"type": "string"},
                    "input_sources": {
                        "type": "array", 
                        "items": {"type": "string"},
                        "enum": ["user_input", "file", "network", "registry", "command_line"]
                    }
                },
                "required": ["job_id"]
            }
        }
    },
    {
        "type": "function", 
        "function": {
            "name": "assess_privilege_escalation", 
            "description": "Assess privilege escalation vectors",
            "parameters": {
                "type": "object", 
                "properties": {
                    "job_id": {"type": "string"},
                    "target_privileges": {
                        "type": "array", 
                        "items": {"type": "string"},
                        "enum": ["admin", "system", "kernel", "service"]
                    }
                },
                "required": ["job_id"]
            }
        }
    }
]

VULNERABILITY_PATTERNS = {
    "buffer_overflow": [
        r"strcpy\s*\(",
        r"strcat\s*\(",
        r"gets\s*\(",
        r"sprintf\s*\(",
        r"scanf\s*\("
    ],
    "heap_corruption": [
        r"malloc\s*\(",
        r"free\s*\(",
        r"realloc\s*\(",
        r"calloc\s*\("
    ],
    "format_string": [
        r"printf\s*\([^,)]*\)",
        r"sprintf\s*\([^,)]*\)",
        r"fprintf\s*\([^,)]*\)"
    ],
    "race_condition": [
        r"CreateFile\s*\(",
        r"OpenFile\s*\(",
        r"CreateMutex\s*\(",
        r"WaitForSingleObject\s*\("
    ]
}

class SecurityAgent:
    def __init__(self):
        self.client = model_manager.client
        self.model = model_manager.model
        
        self.security_tools = {
            "analyze_binary_security": self._analyze_binary_security,
            "detect_memory_corruption": self._detect_memory_corruption,
            "scan_dangerous_apis": self._scan_dangerous_apis,
            "analyze_control_flow": self._analyze_control_flow,
            "check_input_validation": self._check_input_validation,
            "assess_privilege_escalation": self._assess_privilege_escalation,
        }
        
        self.security_dir = os.path.join(os.path.dirname(__file__), "security_analysis")
        if not os.path.exists(self.security_dir):
            try:
                os.makedirs(self.security_dir)
            except OSError as e:
                console.print(f"[red]Error creating security directory: {e}[/red]")
                self.security_dir = None

    def _get_security_file(self, job_id: str) -> str:
        return os.path.join(self.security_dir, f"{job_id}_security.json")

    def load_security_history(self, job_id: str) -> list:
        security_file = self._get_security_file(job_id)
        if os.path.exists(security_file):
            try:
                with open(security_file, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError) as e:
                console.print(f"[red]Error loading security history: {e}[/red]")
        return []

    def save_security_analysis(self, job_id: str, analysis: dict):
        security_file = self._get_security_file(job_id)
        with open(security_file, 'w') as f:
            json.dump(analysis, f, indent=2)

    def clear_security_history(self, job_id: str) -> bool:
        """Clear security analysis history for a specific job"""
        security_file = self._get_security_file(job_id)
        if os.path.exists(security_file):
            try:
                os.remove(security_file)
                return True
            except IOError as e:
                console.print(f"[red]Error clearing security history: {e}[/red]")
                return False
        return True

    def _call_ghidra_api(self, endpoint: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        try:
            job_id = payload.get("job_id", "")
            if endpoint == "list_functions":
                url = f"{GHIDRA_API_BASE}/results/{job_id}/functions"
            elif endpoint == "list_imports":
                url = f"{GHIDRA_API_BASE}/results/{job_id}/imports"
            elif endpoint == "list_strings":
                url = f"{GHIDRA_API_BASE}/results/{job_id}/strings"
            elif endpoint == "decompile_function":
                addr = payload.get("addr", "")
                url = f"{GHIDRA_API_BASE}/results/{job_id}/function/{addr}/decompile"
            elif endpoint == "get_xrefs":
                addr = payload.get("addr", "")
                url = f"{GHIDRA_API_BASE}/results/{job_id}/xrefs/{addr}"
            elif endpoint == "query_artifacts":
                url = f"{GHIDRA_API_BASE}/query"
            else:
                url = f"{GHIDRA_API_BASE}/tools/{endpoint}"
            
            if endpoint in ["list_functions", "list_imports", "list_strings"]:
                response = requests.get(url, params=payload)
            elif endpoint == "query_artifacts":
                response = requests.post(url, json=payload)
            else:
                response = requests.get(url)
            
            response.raise_for_status()
            try:
                return response.json()
            except json.JSONDecodeError:
                return {"result": response.text}
        except requests.exceptions.RequestException as e:
            return {"error": f"API call to {endpoint} failed: {str(e)}"}

    def _analyze_binary_security(self, job_id: str, file_type: str = "unknown", analysis_depth: str = "standard") -> Dict[str, Any]:
        analysis = {
            "job_id": job_id,
            "file_type": file_type,
            "analysis_depth": analysis_depth,
            "timestamp": str(os.times()),
            "vulnerabilities": [],
            "risk_score": 0,
            "recommendations": []
        }
        
        functions = self._call_ghidra_api("list_functions", {"job_id": job_id, "limit": 100})
        if "functions" in functions:
            analysis["function_count"] = len(functions["functions"])
            
            suspicious_funcs = [f for f in functions["functions"] if any(keyword in f["name"].lower() 
                             for keyword in ["admin", "priv", "escal", "debug", "test", "backdoor"])]
            analysis["suspicious_functions"] = suspicious_funcs
        
        imports = self._call_ghidra_api("list_imports", {"job_id": job_id})
        if "imports" in imports:
            dangerous_imports = [imp for imp in imports["imports"] if any(keyword in imp["symbol"].lower() 
                              for keyword in ["create", "write", "exec", "shell", "system", "priv"])]
            analysis["dangerous_imports"] = dangerous_imports
        
        return analysis

    def _detect_memory_corruption(self, job_id: str, check_types: List[str] = None) -> Dict[str, Any]:
        if check_types is None:
            check_types = ["buffer_overflow", "heap_overflow", "use_after_free"]
        
        result = {"job_id": job_id, "memory_vulnerabilities": []}
        
        strings = self._call_ghidra_api("list_strings", {"job_id": job_id, "min_length": 5})
        if "strings" in strings:
            for pattern_name, patterns in VULNERABILITY_PATTERNS.items():
                if pattern_name in check_types:
                    for pattern in patterns:
                        for string in strings["strings"]:
                            if re.search(pattern, string, re.IGNORECASE):
                                result["memory_vulnerabilities"].append({
                                    "type": pattern_name,
                                    "pattern": pattern,
                                    "match": string,
                                    "severity": "high" if pattern_name in ["buffer_overflow", "heap_overflow"] else "medium"
                                })
        
        return result

    def _scan_dangerous_apis(self, job_id: str, api_categories: List[str] = None) -> Dict[str, Any]:
        if api_categories is None:
            api_categories = ["memory", "string", "file", "network"]
        
        result = {"job_id": job_id, "dangerous_apis": []}
        
        imports = self._call_ghidra_api("list_imports", {"job_id": job_id})
        if "imports" in imports:
            dangerous_apis = {
                "memory": ["malloc", "free", "memcpy", "memset", "strcpy", "strcat"],
                "string": ["sprintf", "vsprintf", "scanf", "gets"],
                "file": ["CreateFile", "WriteFile", "DeleteFile", "MoveFile"],
                "network": ["socket", "connect", "bind", "listen", "accept"],
                "crypto": ["CryptEncrypt", "CryptDecrypt", "CryptCreateHash"],
                "process": ["CreateProcess", "ShellExecute", "WinExec"]
            }
            
            for imp in imports["imports"]:
                for category, apis in dangerous_apis.items():
                    if category in api_categories:
                        for api in apis:
                            if api.lower() in imp["symbol"].lower():
                                result["dangerous_apis"].append({
                                    "category": category,
                                    "api": imp["symbol"],
                                    "library": imp.get("library", "unknown"),
                                    "risk": "high" if category in ["memory", "process"] else "medium"
                                })
        
        return result

    def _analyze_control_flow(self, job_id: str, function_addr: str = None) -> Dict[str, Any]:
        result = {"job_id": job_id, "control_flow_issues": []}
        
        functions = self._call_ghidra_api("list_functions", {"job_id": job_id, "limit": 50})
        if "functions" in functions:
            for func in functions["functions"][:10]:
                addr = func["address"]
                
                xrefs = self._call_ghidra_api("get_xrefs", {"job_id": job_id, "addr": addr})
                if "callers" in xrefs or "callees" in xrefs:
                    callers = xrefs.get("callers", [])
                    callees = xrefs.get("callees", [])
                    
                    if len(callers) > 10:
                        result["control_flow_issues"].append({
                            "function": func["name"],
                            "address": addr,
                            "issue": "High call complexity",
                            "callers_count": len(callers),
                            "callees_count": len(callees),
                            "severity": "medium"
                        })
        
        return result

    def _check_input_validation(self, job_id: str, input_sources: List[str] = None) -> Dict[str, Any]:
        if input_sources is None:
            input_sources = ["user_input", "file", "network"]
        
        result = {"job_id": job_id, "input_validation_issues": []}
        
        functions = self._call_ghidra_api("list_functions", {"job_id": job_id, "limit": 100})
        if "functions" in functions:
            input_functions = [f for f in functions["functions"] if any(keyword in f["name"].lower() 
                           for keyword in ["read", "input", "recv", "get", "parse", "process"])]
            
            for func in input_functions:
                decompiled = self._call_ghidra_api("decompile_function", {"job_id": job_id, "addr": func["address"]})
                if "pseudocode" in decompiled:
                    code = decompiled["pseudocode"].lower()
                    
                    has_validation = any(pattern in code for pattern in ["if", "check", "validate", "verify", "length", "size"])
                    has_bounds_check = any(pattern in code for pattern in ["sizeof", "length", "size", "count"])
                    
                    if not has_validation or not has_bounds_check:
                        result["input_validation_issues"].append({
                            "function": func["name"],
                            "address": func["address"],
                            "issue": "Insufficient input validation",
                            "has_validation": has_validation,
                            "has_bounds_check": has_bounds_check,
                            "severity": "high" if not has_validation else "medium"
                        })
        
        return result

    def _assess_privilege_escalation(self, job_id: str, target_privileges: List[str] = None) -> Dict[str, Any]:
        if target_privileges is None:
            target_privileges = ["admin", "system", "kernel"]
        
        result = {"job_id": job_id, "privilege_escalation_vectors": []}
        
        functions = self._call_ghidra_api("list_functions", {"job_id": job_id, "limit": 100})
        if "functions" in functions:
            priv_functions = [f for f in functions["functions"] if any(keyword in f["name"].lower() 
                          for keyword in ["admin", "priv", "escal", "token", "imperson", "debug", "system"])]
            
            for func in priv_functions:
                xrefs = self._call_ghidra_api("get_xrefs", {"job_id": job_id, "addr": func["address"]})
                
                result["privilege_escalation_vectors"].append({
                    "function": func["name"],
                    "address": func["address"],
                    "callers": len(xrefs.get("callers", [])),
                    "callees": len(xrefs.get("callees", [])),
                    "severity": "high" if "admin" in func["name"].lower() or "system" in func["name"].lower() else "medium"
                })
        
        imports = self._call_ghidra_api("list_imports", {"job_id": job_id})
        if "imports" in imports:
            priv_imports = [imp for imp in imports["imports"] if any(keyword in imp["symbol"].lower() 
                          for keyword in ["adjust", "token", "priv", "debug", "se", "imperson"])]
            
            for imp in priv_imports:
                result["privilege_escalation_vectors"].append({
                    "type": "import",
                    "api": imp["symbol"],
                    "library": imp.get("library", "unknown"),
                    "severity": "high" if "token" in imp["symbol"].lower() else "medium"
                })
        
        return result

    def security_analysis_stream(self, user_message: str, job_id: str) -> Generator[str, None, None]:
        history = self.load_security_history(job_id)
        
        if not history:
            history.append({"role": "system", "content": SECURITY_SYSTEM_PROMPT})

        history.append({"role": "user", "content": f"[Security Analysis - Job ID: {job_id}] {user_message}"})
        messages = history

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                tools=SECURITY_TOOLS,
                tool_choice="auto"
            )

            message = response.choices[0].message
            messages.append(message)

            if message.tool_calls:
                for tool_call in message.tool_calls:
                    function_name = tool_call.function.name
                    if function_name in self.security_tools:
                        yield json.dumps({"type": "tool_call", "description": f"Running security analysis: {function_name}..."})

                        try:
                            args = json.loads(tool_call.function.arguments)
                        except json.JSONDecodeError as e:
                            console.print(f"[red]JSON parsing error: {e}[/red]")
                            args = {}

                        args['job_id'] = job_id

                        tool_result = self.security_tools[function_name](**args)

                        messages.append({
                            "tool_call_id": tool_call.id,
                            "role": "tool",
                            "name": function_name,
                            "content": json.dumps(tool_result)
                        })

            stream = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                stream=True
            )

            complete_response_content = ""
            for chunk in stream:
                content = chunk.choices[0].delta.content
                if content:
                    complete_response_content += content
                    yield json.dumps({"type": "token", "content": content})

            messages.append({"role": "assistant", "content": complete_response_content})

            self.save_security_analysis(job_id, {
                "timestamp": str(os.times()),
                "analysis": complete_response_content,
                "tools_used": [tc.function.name for tc in message.tool_calls] if message.tool_calls else []
            })

        except Exception as e:
            yield json.dumps({"type": "error", "content": f"Security Analysis Error: {str(e)}"})

    def generate_security_report(self, job_id: str) -> Dict[str, Any]:
        analysis = self.load_security_history(job_id)
        
        report = {
            "job_id": job_id,
            "timestamp": str(os.times()),
            "executive_summary": "",
            "vulnerabilities": [],
            "risk_score": 0,
            "recommendations": [],
            "cvss_scores": {}
        }
        
        analyses = [
            self._analyze_binary_security(job_id),
            self._detect_memory_corruption(job_id),
            self._scan_dangerous_apis(job_id),
            self._check_input_validation(job_id),
            self._assess_privilege_escalation(job_id)
        ]
        
        for analysis_result in analyses:
            if "error" not in analysis_result:
                report["vulnerabilities"].extend(analysis_result.get("vulnerabilities", []))
                report["vulnerabilities"].extend(analysis_result.get("memory_vulnerabilities", []))
                report["vulnerabilities"].extend(analysis_result.get("dangerous_apis", []))
                report["vulnerabilities"].extend(analysis_result.get("input_validation_issues", []))
                report["vulnerabilities"].extend(analysis_result.get("privilege_escalation_vectors", []))
        
        high_vulns = len([v for v in report["vulnerabilities"] if v.get("severity") == "high"])
        medium_vulns = len([v for v in report["vulnerabilities"] if v.get("severity") == "medium"])
        low_vulns = len([v for v in report["vulnerabilities"] if v.get("severity") == "low"])
        
        report["risk_score"] = min(10, (high_vulns * 3) + (medium_vulns * 2) + (low_vulns * 1))
        report["risk_level"] = "Critical" if report["risk_score"] >= 8 else "High" if report["risk_score"] >= 5 else "Medium" if report["risk_score"] >= 2 else "Low"
        
        return report
