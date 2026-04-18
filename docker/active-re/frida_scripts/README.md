# Frida Instrumentation Scripts

This directory contains pre-defined Frida instrumentation scripts for Active Reverse Engineering.

## Available Scripts

### 1. api_tracing.js
- Traces common API calls including file operations, registry operations, and network operations
- Captures function arguments and backtraces
- Useful for understanding program behavior and identifying suspicious activity

### 2. memory_tracking.js
- Monitors memory allocations (malloc) and deallocations (free)
- Captures allocation sizes and call sites
- Useful for detecting memory leaks and heap corruption

### 3. network_monitoring.js
- Monitors network operations (socket, connect, send, recv)
- Captures IP addresses and ports
- Useful for identifying network communication patterns

### 4. file_monitoring.js
- Monitors file operations (CreateFile, ReadFile, WriteFile)
- Captures file paths and handles
- Useful for tracking file system access

### 5. anti_debug.js
- Detects anti-debugging techniques and debugger presence
- Performs periodic checks for Frida agent and timing anomalies
- Useful for analyzing anti-debugging protections

## Usage

These scripts can be loaded via the Frida instrumentation module in the Active RE service:

```python
from core.frida_instrumentation import get_frida

frida = get_frida()
frida.load_script_file("path/to/script.js")
```

Or use the pre-defined templates:

```python
from core.frida_instrumentation import FridaScriptTemplates

frida.load_script(FridaScriptTemplates.api_call_tracing())
```
