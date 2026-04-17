import os
import json
import logging
import structlog
import subprocess
from typing import Optional, Dict, Any, List
from pathlib import Path

from core.config import settings

log = structlog.get_logger()


class PwndbgBridge:
    """wrapper for pwndbg debugging integration"""

    def __init__(self, gdb_path: str = None):
        self.gdb_path = gdb_path or settings.PWNBG_GDB_PATH
        self.current_process = None
        self.gdb_process = None

        if not Path(self.gdb_path).exists():
            log.warning(f"GDB not found at {self.gdb_path}, pwndbg integration will be disabled")
            return


        log.info("pwndbg bridge initialized successfully")

    def start_debugging(self, binary_path: str, args: List[str] = None) -> bool:
        """Start GDB with pwndbg for binary debugging"""
        if not Path(self.gdb_path).exists():
            log.error("GDB not available")
            return False

        try:
            cmd = [self.gdb_path]
            
            if self.pwndbg_path.exists():
                pwndbg_init = self.pwndbg_path / "gdbinit.py"
                if pwndbg_init.exists():
                    cmd.extend(["-x", str(pwndbg_init)])

            cmd.append(binary_path)

            if args:
                cmd.extend(["--args"])
                cmd.extend(args)

            self.gdb_process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            log.info(f"Started pwndbg debugging for {binary_path}")
            return True

        except Exception as e:
            log.error(f"Failed to start debugging: {e}", exc_info=True)
            return False

    def execute_command(self, command: str) -> Dict[str, Any]:
        """Execute GDB/pwndbg command"""
        if not self.gdb_process:
            return {"error": "No GDB process running"}

        try:
            self.gdb_process.stdin.write(command + "\n")
            self.gdb_process.stdin.flush()

            output = self.gdb_process.stdout.readline()
            error = self.gdb_process.stderr.readline()

            return {
                "command": command,
                "output": output,
                "error": error if error else None
            }
        except Exception as e:
            log.error(f"Failed to execute command {command}: {e}", exc_info=True)
            return {"error": str(e)}

    def get_heap_info(self) -> Optional[Dict[str, Any]]:
        """Get heap information using pwndbg heap commands"""
        if not self.gdb_process:
            return None

        try:
            result = self.execute_command("heap")
            
            if result.get("error"):
                return {"error": result["error"]}

            heap_info = {
                "output": result.get("output"),
                "arenas": [],
                "chunks": [],
                "parsed": {}
            }

            arena_result = self.execute_command("arenas")
            if not arena_result.get("error"):
                heap_info["arenas"].append(arena_result.get("output"))
              
                heap_info["parsed"]["arenas"] = self._parse_arena_output(arena_result.get("output"))

            chunk_result = self.execute_command("bins")
            if not chunk_result.get("error"):
                heap_info["chunks"].append(chunk_result.get("output"))
               
                heap_info["parsed"]["chunks"] = self._parse_chunk_output(chunk_result.get("output"))

            return heap_info

        except Exception as e:
            log.error(f"Failed to get heap info: {e}", exc_info=True)
            return None

    def get_memory_layout(self) -> Optional[Dict[str, Any]]:
        """Get memory layout using vmmap"""
        if not self.gdb_process:
            return None

        try:
            result = self.execute_command("vmmap")
            
            if result.get("error"):
                return {"error": result["error"]}

            memory_regions = []
            for line in result.get("output", "").split("\n"):
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 4:
                        memory_regions.append({
                            "start": parts[0],
                            "end": parts[1],
                            "perms": parts[2],
                            "name": " ".join(parts[3:])
                        })

            return {"regions": memory_regions}

        except Exception as e:
            log.error(f"Failed to get memory layout: {e}", exc_info=True)
            return None

    def set_breakpoint(self, address: str, condition: str = None) -> bool:
        """Set breakpoint at address"""
        if not self.gdb_process:
            return False

        try:
            cmd = f"break *{address}"
            if condition:
                cmd += f" if {condition}"

            result = self.execute_command(cmd)
            return not result.get("error")

        except Exception as e:
            log.error(f"Failed to set breakpoint: {e}", exc_info=True)
            return False

    def get_registers(self) -> Optional[Dict[str, Any]]:
        """Get register values"""
        if not self.gdb_process:
            return None

        try:
            result = self.execute_command("regs")
            
            if result.get("error"):
                return {"error": result["error"]}

            registers = {}
            for line in result.get("output", "").split("\n"):
                if " " in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        registers[parts[0]] = parts[1]

            return registers

        except Exception as e:
            log.error(f"Failed to get registers: {e}", exc_info=True)
            return None

    def get_backtrace(self) -> Optional[List[str]]:
        """Get backtrace"""
        if not self.gdb_process:
            return None

        try:
            result = self.execute_command("bt")
            
            if result.get("error"):
                return None

            frames = []
            for line in result.get("output", "").split("\n"):
                if line.strip():
                    frames.append(line.strip())

            return frames

        except Exception as e:
            log.error(f"Failed to get backtrace: {e}", exc_info=True)
            return None

    def step_instruction(self) -> bool:
        """Step one instruction"""
        if not self.gdb_process:
            return False

        try:
            result = self.execute_command("si")
            return not result.get("error")
        except Exception as e:
            log.error(f"Failed to step: {e}", exc_info=True)
            return False

    def continue_execution(self) -> bool:
        """Continue execution"""
        if not self.gdb_process:
            return False

        try:
            result = self.execute_command("c")
            return not result.get("error")
        except Exception as e:
            log.error(f"Failed to continue: {e}", exc_info=True)
            return False

    def stop_debugging(self) -> bool:
        """Stop debugging session"""
        if not self.gdb_process:
            return True

        try:
            self.execute_command("quit")
            self.gdb_process.wait(timeout=5)
            self.gdb_process = None
            log.info("Stopped debugging session")
            return True
        except Exception as e:
            log.error(f"Failed to stop debugging: {e}", exc_info=True)
            try:
                self.gdb_process.kill()
                self.gdb_process = None
            except:
                pass
            return False

    def is_available(self) -> bool:
        """Check if pwndbg is available"""
        return Path(self.gdb_path).exists()

    def _parse_arena_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse pwndbg arena output"""
        arenas = []
        for line in output.split('\n'):
            if 'arena' in line.lower():
                parts = line.split()
                if len(parts) >= 2:
                    arenas.append({
                        "address": parts[0],
                        "size": parts[1] if len(parts) > 1 else "unknown"
                    })
        return arenas

    def _parse_chunk_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse pwndbg chunk output"""
        chunks = []
        for line in output.split('\n'):
            if 'chunk' in line.lower() or 'free' in line.lower():
                parts = line.split()
                if len(parts) >= 2:
                    chunks.append({
                        "address": parts[0],
                        "size": parts[1] if len(parts) > 1 else "unknown",
                        "status": "free" if "free" in line.lower() else "allocated"
                    })
        return chunks

    def auto_exploit_pattern(self, pattern: str) -> Dict[str, Any]:
        """Automatically test exploit pattern"""
        if not self.gdb_process:
            return {"error": "No GDB process running"}

        try:
         
            self.execute_command(f"cyclic {len(pattern)}")
        
            result = self.execute_command(f"cyclic -l {pattern}")
            
            return {
                "pattern": pattern,
                "offset": result.get("output", "").strip(),
                "status": "success" if not result.get("error") else "failed"
            }
        except Exception as e:
            log.error(f"Failed to auto exploit pattern: {e}", exc_info=True)
            return {"error": str(e)}

    def get_all_breakpoints(self) -> List[Dict[str, Any]]:
        """Get all breakpoints"""
        if not self.gdb_process:
            return []

        try:
            result = self.execute_command("info breakpoints")
            breakpoints = []
            
            for line in result.get("output", "").split('\n'):
                if line.strip() and 'Num' not in line and '---' not in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        breakpoints.append({
                            "number": parts[0],
                            "type": parts[1],
                            "disp": parts[2],
                            "enabled": parts[3] if len(parts) > 3 else "y",
                            "address": parts[4] if len(parts) > 4 else "unknown"
                        })
            
            return breakpoints
        except Exception as e:
            log.error(f"Failed to get breakpoints: {e}", exc_info=True)
            return []


_pwndbg_instance: Optional[PwndbgBridge] = None


def get_pwndbg() -> PwndbgBridge:
    """Get or create pwndbg bridge instance"""
    global _pwndbg_instance
    if _pwndbg_instance is None:
        _pwndbg_instance = PwndbgBridge()
    return _pwndbg_instance
