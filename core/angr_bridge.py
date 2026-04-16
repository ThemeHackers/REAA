import os
import logging
import structlog
from typing import Optional, Dict, Any, List
from pathlib import Path

try:
    import angr
    import angr.exploration_techniques as et
    ANGR_AVAILABLE = True
except ImportError:
    ANGR_AVAILABLE = False

from core.config import settings

log = structlog.get_logger()


class AngrBridge:
    """wrapper for angr symbolic execution and binary analysis"""

    def __init__(self):
        self.project = None
        self.simgr = None
        self.initial_state = None

        if not ANGR_AVAILABLE:
            log.warning("angr not available, symbolic execution will be disabled")
            return

        log.info("angr initialized successfully")

    def load_binary(self, binary_path: str, auto_load_libs: bool = False) -> bool:
        """Load a binary into angr project"""
        if not ANGR_AVAILABLE:
            return False

        try:
            self.project = angr.Project(binary_path, auto_load_libs=auto_load_libs)
            log.info(f"Loaded binary: {binary_path}")
            return True
        except Exception as e:
            log.error(f"Failed to load binary {binary_path}: {e}", exc_info=True)
            return False

    def create_initial_state(self, addr: int = None) -> bool:
        """Create initial simulation state"""
        if not self.project:
            log.error("No project loaded")
            return False

        try:
            if addr:
                self.initial_state = self.project.factory.blank_state(addr=addr)
            else:
                self.initial_state = self.project.factory.entry_state()
            log.info("Created initial state")
            return True
        except Exception as e:
            log.error(f"Failed to create initial state: {e}", exc_info=True)
            return False

    def create_simulation_manager(self, state=None) -> bool:
        """Create simulation manager for symbolic execution"""
        if not self.project:
            log.error("No project loaded")
            return False

        try:
            sim_state = state if state else self.initial_state
            self.simgr = self.project.factory.simgr(sim_state)
            log.info("Created simulation manager")
            return True
        except Exception as e:
            log.error(f"Failed to create simulation manager: {e}", exc_info=True)
            return False

    def run_symbolic_execution(
        self,
        max_steps: int = 1000,
        timeout: int = 300
    ) -> Dict[str, Any]:
        """Run symbolic execution with exploration techniques"""
        if not self.simgr:
            log.error("No simulation manager")
            return {"error": "No simulation manager"}

        try:
            self.simgr.use_technique(et.Explorer(find=[], avoid=[]))
            self.simgr.use_technique(et.LengthLimiter(max_steps=max_steps))
            self.simgr.use_technique(et.Timeout(timeout=timeout))

            self.simgr.run()

            results = {
                "active": len(self.simgr.active),
                "deadended": len(self.simgr.deadended),
                "errored": len(self.simgr.errored),
                "found": len(self.simgr.found)
            }

            log.info(f"Symbolic execution completed: {results}")
            return results
        except Exception as e:
            log.error(f"Symbolic execution failed: {e}", exc_info=True)
            return {"error": str(e)}

    def get_control_flow_graph(self) -> Optional[Dict[str, Any]]:
        """Get control flow graph"""
        if not self.project:
            log.error("No project loaded")
            return None

        try:
            cfg = self.project.analyses.CFGFast()
            nodes = []
            edges = []

            for node in cfg.nodes():
                nodes.append({
                    "addr": hex(node.addr),
                    "size": node.size,
                    "block_id": node.block_id
                })

            for edge in cfg.graph.edges():
                edges.append({
                    "src": hex(edge[0].addr),
                    "dst": hex(edge[1].addr)
                })

            return {
                "nodes": nodes,
                "edges": edges
            }
        except Exception as e:
            log.error(f"Failed to get CFG: {e}", exc_info=True)
            return None

    def get_data_dependencies(self, addr: int) -> Optional[Dict[str, Any]]:
        """Get data dependencies for an address"""
        if not self.project:
            log.error("No project loaded")
            return None

        try:
            ddg = self.project.analyses.DDG()
            node = ddg.get_node(addr)

            if node:
                dependencies = {
                    "addr": hex(addr),
                    "data_dependents": [hex(d.addr) for d in node.data_dependents],
                    "data_dependencies": [hex(d.addr) for d in node.data_dependencies]
                }
                return dependencies

            return None
        except Exception as e:
            log.error(f"Failed to get data dependencies: {e}", exc_info=True)
            return None

    def get_function_at(self, addr: int) -> Optional[Dict[str, Any]]:
        """Get function information at address"""
        if not self.project:
            log.error("No project loaded")
            return None

        try:
            cfg = self.project.analyses.CFGFast()
            function = cfg.functions.get(addr)

            if function:
                return {
                    "addr": hex(function.addr),
                    "name": function.name,
                    "size": function.size,
                    "num_blocks": len(function.blocks),
                    "callers": [hex(c.addr) for c in function.callers],
                    "callees": [hex(c.addr) for c in function.callees]
                }

            return None
        except Exception as e:
            log.error(f"Failed to get function: {e}", exc_info=True)
            return None

    def explore_paths(
        self,
        start_addr: int,
        find_addrs: List[int],
        avoid_addrs: List[int] = None
    ) -> Dict[str, Any]:
        """Explore paths from start address to find addresses"""
        if not self.project:
            log.error("No project loaded")
            return {"error": "No project loaded"}

        try:
            state = self.project.factory.blank_state(addr=start_addr)
            simgr = self.project.factory.simgr(state)

            simgr.use_technique(et.Explorer(find=find_addrs, avoid=avoid_addrs or []))
            simgr.use_technique(et.LengthLimiter(max_steps=1000))
            simgr.use_technique(et.Timeout(timeout=settings.ANGR_SYMBOLIC_EXECUTION_TIMEOUT))

            simgr.run()

            results = {
                "found": len(simgr.found),
                "found_states": [
                    {
                        "addr": hex(s.addr),
                        "constraints": str(s.solver.constraints)
                    }
                    for s in simgr.found
                ]
            }

            log.info(f"Path exploration completed: {results}")
            return results
        except Exception as e:
            log.error(f"Path exploration failed: {e}", exc_info=True)
            return {"error": str(e)}

    def get_strings(self) -> List[Dict[str, Any]]:
        """Get strings from binary"""
        if not self.project:
            log.error("No project loaded")
            return []

        try:
            strings = []
            for segment in self.project.loader.main_object.segments:
                if segment.is_readable:
                    data = self.project.loader.memory.load(segment.min_addr, segment.max_addr - segment.min_addr)
                    for addr, string in self.project.loader.main_object.strings(data):
                        strings.append({
                            "addr": hex(segment.min_addr + addr),
                            "string": string
                        })

            return strings
        except Exception as e:
            log.error(f"Failed to get strings: {e}", exc_info=True)
            return []

    def is_available(self) -> bool:
        """Check if angr is available"""
        return ANGR_AVAILABLE


_angr_instance: Optional[AngrBridge] = None


def get_angr() -> AngrBridge:
    """Get or create angr bridge instance"""
    global _angr_instance
    if _angr_instance is None:
        _angr_instance = AngrBridge()
    return _angr_instance
