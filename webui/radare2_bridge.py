"""
Radare2 Bridge - Interface between Flask application and radare2 CLI
"""
import subprocess
import json
import os
import tempfile
import shutil
import sys
from typing import Optional, Dict, List, Any
from rich.console import Console

console = Console()


class Radare2Bridge:
    """Bridge for interacting with radare2 CLI"""
    
    def __init__(self, r2_path: str = None):
        if r2_path:
            self.r2_path = r2_path
            if os.path.exists(r2_path):
                console.print(f"[cyan]Using custom radare2 path: {r2_path}[/cyan]")
            else:
                console.print(f"[yellow]Using provided radare2 path (may not exist): {r2_path}[/yellow]")
        elif sys.platform == 'win32':
            project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            r2_bat_path = os.path.join(project_root, 'radare2-6.1.2-w64', 'bin', 'r2.bat')
            r2_exe_path = os.path.join(project_root, 'radare2-6.1.2-w64', 'bin', 'r2.exe')

            if os.path.exists(r2_bat_path):
                self.r2_path = r2_bat_path
                console.print(f"[cyan]Using project radare2 (r2.bat): {r2_bat_path}[/cyan]")
            elif os.path.exists(r2_exe_path):
                self.r2_path = r2_exe_path
                console.print(f"[cyan]Using project radare2 (r2.exe): {r2_exe_path}[/cyan]")
            else:
                self.r2_path = "r2"
                console.print("[cyan][OK] Using system radare2 from PATH[/cyan]")
        else:
            self.r2_path = "r2"
            console.print("[cyan][OK] Using system radare2 from PATH[/cyan]")
        
        self.current_file = None
        self.temp_dir = None
        
        self.asm_config = {
            'asm.bytes': True,
            'asm.bytespace': True,
            'asm.capitalize': False,
            'asm.cmt.col': 80,
            'asm.cmt.right': True,
            'asm.comments': True,
            'asm.demangle': True,
            'asm.describe': True,
            'asm.filter': True,
            'asm.flags': True,
            'asm.fcnlines': True,
            'asm.calls': True,
            'scr.color': 1,
            'scr.color.bytes': True,
            'scr.color.ops': True,
        }
        
    def check_r2_available(self) -> bool:
        """Check if radare2 is installed and accessible"""
        try:
            result = subprocess.run([self.r2_path, "-v"], 
                                    capture_output=True, 
                                    text=True, 
                                    timeout=5)
            if result.returncode == 0:
                return True
            result = subprocess.run([self.r2_path, "-version"], 
                                    capture_output=True, 
                                    text=True, 
                                    timeout=5)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    def get_version(self) -> str:
        """Get radare2 version string"""
        try:
            result = subprocess.run([self.r2_path, "-v"],
                                    capture_output=True,
                                    text=True,
                                    timeout=5)
            if result.returncode == 0 and result.stdout:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if 'radare2' in line.lower():
                        return line.strip()
            result = subprocess.run([self.r2_path, "-version"],
                                    capture_output=True,
                                    text=True,
                                    timeout=5)
            if result.returncode == 0 and result.stdout:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if 'radare2' in line.lower():
                        return line.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return "Unknown"
    
    def get_entry_point(self) -> str:
        """Get entry point address"""
        try:
            result = subprocess.run([self.r2_path, "-q", "-c", "ie"],
                                    capture_output=True,
                                    text=True,
                                    timeout=10)
            if result.returncode == 0 and result.stdout:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if line.startswith('nth') or line.startswith('―'):
                        continue
                    parts = line.split()
                    if len(parts) >= 3:
                        import re
                        match = re.search(r'0x[0-9a-fA-F]+', parts[2])
                        if match:
                            return match.group(0)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return None
    
    def get_file_info(self) -> Dict[str, Any]:
        """Get file information including base address"""
        try:
            result = subprocess.run([self.r2_path, "-q", "-c", "iI"],
                                    capture_output=True,
                                    text=True,
                                    timeout=10)
            if result.returncode == 0 and result.stdout:
                info = {}
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if 'baddr' in line.lower() or 'base' in line.lower():
                        import re
                        match = re.search(r'0x[0-9a-fA-F]+', line)
                        if match:
                            info['baddr'] = match.group(0)
                return info
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return {}
    
    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """Analyze a file using radare2"""
        if not os.path.exists(file_path):
            return {"error": "File not found"}
        
        try:
            self.temp_dir = tempfile.mkdtemp(prefix="r2_analysis_")
            
            temp_file = os.path.join(self.temp_dir, os.path.basename(file_path))
            shutil.copy2(file_path, temp_file)
            self.current_file = temp_file
            
            result = subprocess.run(
                [self.r2_path, "-q", "-c", "iI; aa", temp_file],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            return {
                "success": True,
                "output": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode
            }
            
        except subprocess.TimeoutExpired:
            self.cleanup()
            return {"error": "Analysis timeout - file may be too large or corrupted"}
        except Exception as e:
            self.cleanup()
            return {"error": str(e)}

    def load_file_only(self, file_path: str) -> Dict[str, Any]:
        """Load file into radare2 without analysis - faster loading"""
        if not os.path.exists(file_path):
            return {"error": "File not found"}
        
        try:
            self.temp_dir = tempfile.mkdtemp(prefix="r2_analysis_")
            
            temp_file = os.path.join(self.temp_dir, os.path.basename(file_path))
            shutil.copy2(file_path, temp_file)
            self.current_file = temp_file
            
            result = subprocess.run(
                [self.r2_path, "-q", "-c", "iI", temp_file],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            return {
                "success": True,
                "output": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode
            }
            
        except subprocess.TimeoutExpired:
            self.cleanup()
            return {"error": "File info timeout - file may be corrupted"}
        except Exception as e:
            self.cleanup()
            return {"error": str(e)}
    
    def execute_command(self, command: str, use_enhanced_format: bool = False) -> Dict[str, Any]:
        """Execute a radare2 command on current file"""
        if not self.current_file:
            return {"error": "No file loaded"}
        
        try:
            if sys.platform != 'win32':
                cmd = [self.r2_path, "--no-color", "-N", "-q"]
            else:
                cmd = [self.r2_path, "-N", "-q"]
            
            if use_enhanced_format:
                for key, value in self.asm_config.items():
                    if isinstance(value, bool):
                        cmd.extend(["-e", f"{key}={str(value).lower()}"])
                    else:
                        cmd.extend(["-e", f"{key}={value}"])
            else:
                cmd.extend([
                    "-N",
                    "-q"
                ])
            
            cmd.extend(["-c", command, self.current_file])
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            import re
            output = result.stdout
            ansi_escape = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]')
            output = ansi_escape.sub('', output)
            
            return {
                "success": True,
                "output": output,
                "stderr": result.stderr,
                "returncode": result.returncode
            }
            
        except subprocess.TimeoutExpired:
            return {"error": "Command timeout"}
        except Exception as e:
            return {"error": str(e)}
    
    def get_functions(self) -> List[Dict[str, Any]]:
        """Get list of functions from current file"""
        result = self.execute_command("afl")
        if result.get("error"):
            return []
        
        functions = []
        for line in result["output"].split("\n"):
            if line.strip():
                parts = line.split()
                if len(parts) >= 3:
                    functions.append({
                        "address": parts[0],
                        "size": parts[1],
                        "name": " ".join(parts[2:])
                    })
        
        return functions
    
    def get_strings(self) -> List[str]:
        """Get strings from current file"""
        result = self.execute_command("izz")
        if result.get("error"):
            return []
        
        strings = []
        for line in result["output"].split("\n"):
            if line.strip():
                strings.append(line.strip())
        
        return strings
    
    def get_imports(self) -> List[Dict[str, Any]]:
        """Get imports from current file"""
        result = self.execute_command("ii")
        if result.get("error"):
            return []
        
        imports = []
        for line in result["output"].split("\n"):
            if line.strip():
                parts = line.split()
                if len(parts) >= 2:
                    imports.append({
                        "address": parts[0],
                        "name": " ".join(parts[1:])
                    })
        
        return imports
    
    def disassemble_function(self, function_name: str, enhanced: bool = True) -> str:
        """Disassemble a specific function with enhanced formatting"""
        result = self.execute_command(f"pdf @ {function_name}", use_enhanced_format=enhanced)
        if result.get("error"):
            return f"Error: {result['error']}"
        
        return result["output"]
    
    def disassemble_range(self, start_addr: str, end_addr: str, enhanced: bool = True) -> str:
        """Disassemble a range of addresses with enhanced formatting"""
        result = self.execute_command(f"pd {end_addr} @ {start_addr}", use_enhanced_format=enhanced)
        if result.get("error"):
            return f"Error: {result['error']}"
        
        return result["output"]
    
    def disassemble_with_graph(self, function_name: str) -> str:
        """Disassemble with graph view (ascii art)"""
        result = self.execute_command(f"agf @ {function_name}", use_enhanced_format=True)
        if result.get("error"):
            return f"Error: {result['error']}"
        
        return result["output"]
    
    def set_asm_config(self, config: Dict[str, Any]) -> None:
        """Update ASM formatting configuration"""
        self.asm_config.update(config)
    
    def get_asm_config(self) -> Dict[str, Any]:
        """Get current ASM formatting configuration"""
        return self.asm_config.copy()
    
    def apply_preset(self, preset: str) -> None:
        """Apply a formatting preset for different use cases"""
        presets = {
            'minimal': {
                'asm.bytes': False,
                'asm.bytespace': False,
                'asm.cmt.right': False,
                'asm.comments': False,
                'asm.describe': False,
                'asm.flags': False,
                'asm.fcnlines': False,
                'scr.color': 0,
            },
            'detailed': {
                'asm.bytes': True,
                'asm.bytespace': True,
                'asm.cmt.col': 80,
                'asm.cmt.right': True,
                'asm.comments': True,
                'asm.describe': True,
                'asm.filter': True,
                'asm.flags': True,
                'asm.fcnlines': True,
                'asm.calls': True,
                'scr.color': 2,
                'scr.color.bytes': True,
                'scr.color.ops': True,
            },
            'readable': {
                'asm.bytes': True,
                'asm.bytespace': True,
                'asm.capitalize': True,
                'asm.cmt.col': 75,
                'asm.cmt.right': True,
                'asm.comments': True,
                'asm.demangle': True,
                'asm.describe': True,
                'asm.filter': True,
                'scr.color': 1,
            },
            'compact': {
                'asm.bytes': False,
                'asm.bytespace': False,
                'asm.cmt.right': False,
                'asm.fcnlines': False,
                'scr.color': 0,
            }
        }
        
        if preset in presets:
            self.asm_config.update(presets[preset])
        else:
            raise ValueError(f"Unknown preset: {preset}. Available: {list(presets.keys())}")
    
    def get_hexdump(self, address: str, size: int = 256) -> str:
        """Get hexdump at specific address"""
        result = self.execute_command(f"px {size} @ {address}")
        if result.get("error"):
            return f"Error: {result['error']}"
        
        return result["output"]
    
    def cleanup(self):
        """Clean up temporary files"""
        if self.temp_dir and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
            self.temp_dir = None
            self.current_file = None


class Radare2AgentController:
    """Controller for autonomous radare2 operations by AI Agent"""
    
    def __init__(self, bridge: Radare2Bridge):
        self.bridge = bridge
        self.boundaries = {
            "allowed_commands": ["pdf", "afl", "ii", "izz", "px", "iI", "iz", "aaa"],
            "max_execution_time": 300,
            "max_file_size": 100 * 1024 * 1024,
            "read_only": True
        }
        
    def set_boundaries(self, boundaries: Dict[str, Any]):
        """Set user-defined boundaries for autonomous operations"""
        self.boundaries.update(boundaries)
    
    def validate_command(self, command: str) -> bool:
        """Validate if command is allowed within boundaries"""
        cmd_parts = command.split()
        if not cmd_parts:
            return False
        
        base_cmd = cmd_parts[0]
        
        if base_cmd not in self.boundaries["allowed_commands"]:
            return False
        
        if self.boundaries["read_only"]:
            dangerous_commands = ["w", "wa", "wc", "wf", "w+", "oo+"]
            for d in dangerous_commands:
                if d in cmd_parts:
                    return False
        
        return True
    
    def autonomous_analyze(self, analysis_plan: List[str]) -> Dict[str, Any]:
        """Execute autonomous analysis plan"""
        results = []
        
        for step in analysis_plan:
            if not self.validate_command(step):
                results.append({
                    "command": step,
                    "status": "skipped",
                    "reason": "Command not allowed by boundaries"
                })
                continue
            
            result = self.bridge.execute_command(step)
            results.append({
                "command": step,
                "status": "success" if not result.get("error") else "error",
                "output": result.get("output", ""),
                "error": result.get("error", "")
            })
        
        return {
            "success": True,
            "results": results,
            "total_steps": len(analysis_plan),
            "completed": len([r for r in results if r["status"] == "success"])
        }
    
    def get_analysis_summary(self) -> Dict[str, Any]:
        """Get summary of current analysis"""
        return {
            "functions": self.bridge.get_functions(),
            "imports": self.bridge.get_imports(),
            "strings_count": len(self.bridge.get_strings()),
            "file_loaded": self.bridge.current_file is not None
        }
