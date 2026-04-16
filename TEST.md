# Testing Guide for REAA Active Reverse Engineering

This document outlines testing procedures for the Active Reverse Engineering (Active RE) and LLM enhancement features.

## Overview

The Active RE system consists of multiple components that should be tested individually and integrated:

1. Active RE Infrastructure (Docker sandbox, service)
2. Monitoring System (process, memory, network, filesystem)
3. RAG System (vector store, knowledge base, retriever)
4. Multi-Agent System (ActiveREAgent, OrchestratorAgent, ReportAgent)
5. WebUI API Endpoints

## Prerequisites

Before testing, ensure:
- Docker is running and accessible
- All environment variables are configured in `.env`
- Ghidra API is running (if testing integration)
- Ollama is running (for LLM-dependent tests)
- Python dependencies are installed

## Phase 1: Active RE Infrastructure Testing

### 1.1 Docker Sandbox

**Test: Build Active RE Docker image**
```bash
cd docker/active-re
docker-compose build
```
Expected: Image builds successfully without errors

**Test: Start Active RE sandbox**
```bash
docker-compose up -d
```
Expected: Container starts and is healthy
```bash
docker ps
```
Should show `reaa-active-re` container running

**Test: Sandbox health check**
```bash
docker exec reaa-active-re python3 -c "import frida; print('OK')"
```
Expected: Output "OK"

### 1.2 Active RE Service (API Testing)

**Test: Plan execution strategy**
```bash
curl -X POST http://127.0.0.1:5000/api/active-re/plan \
  -H "Content-Type: application/json" \
  -d '{
    "binary_path": "/tmp/test.exe",
    "analysis_goal": "vulnerability detection",
    "binary_type": "exe"
  }'
```
Expected: JSON response with execution plan including mode, steps, and risk assessment

**Test: Start sandbox for analysis**
```bash
curl -X POST http://127.0.0.1:5000/api/active-re/execute \
  -H "Content-Type: application/json" \
  -d '{
    "job_id": "test-job-001",
    "binary_path": "/tmp/test.exe"
  }'
```
Expected: JSON response with execution result or error if binary doesn't exist

**Test: Monitor execution**
```bash
curl -X POST http://127.0.0.1:5000/api/active-re/monitor \
  -H "Content-Type: application/json" \
  -d '{
    "job_id": "test-job-001",
    "duration": 10
  }'
```
Expected: JSON response with monitoring data (process, memory, network)

**Test: Active RE chat**
```bash
curl -X POST http://127.0.0.1:5000/api/active-re/chat \
  -H "Content-Type: application/json" \
  -d '{
    "message": "What are the common API calls in this binary?"
  }'
```
Expected: JSON response with LLM-generated answer

## Phase 2: Monitoring System Testing

### 2.1 Process Monitor (Direct Python Test)

```python
from core.monitoring import ProcessMonitor

monitor = ProcessMonitor()
result = monitor.start_monitoring()
print("Process monitoring result:", result)
```
Expected: Returns process information without errors

### 2.2 Memory Monitor (Direct Python Test)

```python
from core.monitoring import MemoryMonitor

monitor = MemoryMonitor()
result = monitor.take_snapshot(os.getpid())
print("Memory snapshot:", result)
```
Expected: Returns memory snapshot with RSS, VMS, and regions

### 2.3 Network Monitor (Direct Python Test)

```python
from core.monitoring import NetworkMonitor

monitor = NetworkMonitor()
connections = monitor.get_all_connections()
print("Network connections:", len(connections))
```
Expected: Returns list of network connections

### 2.4 Filesystem Monitor (Direct Python Test)

```python
from core.monitoring import FilesystemMonitor

monitor = FilesystemMonitor()
suspicious = monitor.detect_suspicious_files("/tmp")
print("Suspicious files:", suspicious)
```
Expected: Returns list of suspicious files or empty list

## Phase 3: RAG System Testing

### 3.1 Vector Store

**Test: Initialize vector store**
```python
from core.vector_store import get_vector_store

store = get_vector_store()
print("Vector store available:", store.is_available())
```
Expected: Returns True if ChromaDB is installed and configured

**Test: Create collection**
```python
store.create_collection("test_collection")
collections = store.list_collections()
print("Collections:", collections)
```
Expected: "test_collection" appears in list

**Test: Add documents**
```python
store.add_documents(
    collection_name="test_collection",
    documents=["Test document 1", "Test document 2"]
)
print("Document count:", store.get_collection_count("test_collection"))
```
Expected: Document count is 2

**Test: Query documents**
```python
results = store.query(
    collection_name="test_collection",
    query_text="test",
    n_results=1
)
print("Query results:", results)
```
Expected: Returns matching documents

### 3.2 Knowledge Base

**Test: Index function**
```python
from core.knowledge_base import get_knowledge_base

kb = get_knowledge_base()
success = kb.index_function({
    "name": "test_function",
    "address": "0x400000",
    "decompiled_code": "int test() { return 0; }"
})
print("Index function:", success)
```
Expected: Returns True

**Test: Search similar functions**
```python
results = kb.search_similar_functions("int main() { return 0; }")
print("Similar functions:", len(results))
```
Expected: Returns list of similar functions

### 3.3 Retriever

**Test: Retrieve context**
```python
from core.retriever import get_retriever

retriever = get_retriever()
context = retriever.retrieve_context("test query")
print("Context retrieved:", len(context.get("results", {})))
```
Expected: Returns context with relevant documents

## Phase 4: Multi-Agent System Testing

### 4.1 ActiveREAgent (API Testing)

**Test: Plan execution strategy**
```bash
curl -X POST http://127.0.0.1:5000/api/active-re/plan \
  -H "Content-Type: application/json" \
  -d '{
    "binary_path": "/tmp/test.exe",
    "analysis_goal": "dynamic analysis"
  }'
```
Expected: Returns execution plan with steps and tools

### 4.2 OrchestratorAgent (API Testing)

**Test: Plan analysis strategy**
```bash
curl -X POST http://127.0.0.1:5000/api/orchestrator/plan \
  -H "Content-Type: application/json" \
  -d '{
    "binary_path": "/tmp/test.exe",
    "user_request": "Analyze this binary for vulnerabilities"
  }'
```
Expected: Returns strategy with mode, agents, and approval requirements

**Test: Execute orchestrated analysis**
```bash
curl -X POST http://127.0.0.1:5000/api/orchestrator/execute \
  -H "Content-Type: application/json" \
  -d '{
    "job_id": "test-orch-001",
    "binary_path": "/tmp/test.exe",
    "strategy": {
      "mode": "static",
      "agents_to_use": ["ghidra", "security"],
      "requires_approval": false
    }
  }'
```
Expected: Returns task with status and results

**Test: Get pending approvals**
```bash
curl http://127.0.0.1:5000/api/orchestrator/approvals
```
Expected: Returns list of pending approvals (may be empty)

**Test: Approve operation**
```bash
curl -X POST http://127.0.0.1:5000/api/orchestrator/approve \
  -H "Content-Type: application/json" \
  -d '{
    "job_id": "test-orch-001",
    "approved": true
  }'
```
Expected: Returns {"success": true}

**Test: Get all tasks**
```bash
curl http://127.0.0.1:5000/api/orchestrator/tasks
```
Expected: Returns active and historical tasks

### 4.3 ReportAgent (API Testing)

**Test: Generate report**
```bash
curl -X POST http://127.0.0.1:5000/api/report/generate \
  -H "Content-Type: application/json" \
  -d '{
    "job_id": "test-report-001",
    "analysis_results": {
      "binary_path": "/tmp/test.exe",
      "results": {
        "static": {"functions": ["main", "test"]},
        "security": {"vulnerabilities": []}
      }
    },
    "output_format": "json"
  }'
```
Expected: Returns comprehensive report with executive summary, technical details, CVSS score, and recommendations

## Phase 5: RAG API Testing

### 5.1 Search (API Testing)

**Test: Search knowledge base**
```bash
curl -X POST http://127.0.0.1:5000/api/rag/search \
  -H "Content-Type: application/json" \
  -d '{
    "query": "buffer overflow vulnerability",
    "n_results": 5
  }'
```
Expected: Returns relevant documents from knowledge base

**Test: Search similar functions**
```bash
curl -X POST http://127.0.0.1:5000/api/rag/similar-functions \
  -H "Content-Type: application/json" \
  -d '{
    "function_code": "int main() { char buffer[10]; strcpy(buffer, input); return 0; }",
    "n_results": 3
  }'
```
Expected: Returns similar functions with similarity scores

**Test: Search vulnerability patterns**
```bash
curl -X POST http://127.0.0.1:5000/api/rag/vulnerabilities \
  -H "Content-Type: application/json" \
  -d '{
    "code_snippet": "strcpy(buffer, user_input)",
    "n_results": 3
  }'
```
Expected: Returns vulnerability patterns matching the code

## Phase 6: Integration Testing

### 6.1 End-to-End Analysis Workflow

**Test: Complete analysis with orchestrator**
```bash
# Step 1: Upload binary
curl -X POST http://127.0.0.1:5000/upload \
  -F "file=@/path/to/test_binary.exe"

# Step 2: Get job ID from response
JOB_ID="extracted_job_id"

# Step 3: Plan orchestrated analysis
curl -X POST http://127.0.0.1:5000/api/orchestrator/plan \
  -H "Content-Type: application/json" \
  -d "{\"binary_path\": \"test_binary.exe\", \"user_request\": \"Comprehensive analysis\"}"

# Step 4: Execute analysis
curl -X POST http://127.0.0.1:5000/api/orchestrator/execute \
  -H "Content-Type: application/json" \
  -d "{\"job_id\": \"$JOB_ID\", \"binary_path\": \"test_binary.exe\", \"strategy\": {...}}"

# Step 5: Generate report
curl -X POST http://127.0.0.1:5000/api/report/generate \
  -H "Content-Type: application/json" \
  -d "{\"job_id\": \"$JOB_ID\", \"analysis_results\": {...}}"
```

### 6.2 Frida Instrumentation Integration

**Test: Load Frida script**
```python
from core.frida_instrumentation import get_frida, FridaScriptTemplates

frida = get_frida()
success = frida.load_script(FridaScriptTemplates.api_call_tracing())
print("Script loaded:", success)
```
Expected: Returns True

**Test: Attach to process (if available)**
```python
# Requires a running process to test
frida.attach_to_pid(1234)  # Replace with actual PID
messages = frida.get_messages()
print("Messages:", len(messages))
```
Expected: Returns Frida messages if attachment succeeds

## Phase 7: Configuration Testing

### 7.1 Environment Variables

**Test: Verify Active RE settings are loaded**
```python
from core.config import settings

print("ACTIVE_RE_ENABLED:", settings.ACTIVE_RE_ENABLED)
print("ACTIVE_RE_SANDBOX_IMAGE:", settings.ACTIVE_RE_SANDBOX_IMAGE)
print("ANGR_ENABLED:", settings.ANGR_ENABLED)
print("ANGR_LLM_MODEL:", settings.ANGR_LLM_MODEL)
print("PWNBG_ENABLED:", settings.PWNBG_ENABLED)
print("VECTOR_DB_TYPE:", settings.VECTOR_DB_TYPE)
print("ORCHESTRATOR_ENABLED:", settings.ORCHESTRATOR_ENABLED)
```
Expected: All settings reflect values from .env file

### 7.2 Dependency Availability

**Test: Check critical dependencies**
```python
import docker
import frida
import angr
import chromadb
import pyshark

print("docker:", docker.__version__)
print("frida:", frida.__version__)
print("angr:", angr.__version__)
print("chromadb:", chromadb.__version__)
print("pyshark:", pyshark.__version__)
```
Expected: All modules import successfully without errors

## Phase 8: Performance Testing

### 8.1 Response Time Benchmarks

**Test: API response times**
```bash
# Measure response time for each endpoint
time curl -X POST http://127.0.0.1:5000/api/active-re/plan \
  -H "Content-Type: application/json" \
  -d '{"binary_path": "/tmp/test.exe", "analysis_goal": "test"}'

time curl -X POST http://127.0.0.1:5000/api/rag/search \
  -H "Content-Type: application/json" \
  -d '{"query": "test", "n_results": 5}'

time curl -X POST http://127.0.0.1:5000/api/report/generate \
  -H "Content-Type: application/json" \
  -d '{"job_id": "test", "analysis_results": {}}'
```
Expected benchmarks:
- Active RE plan: < 1 second
- RAG search: < 500ms
- Report generation: < 3 seconds

### 8.2 Memory Usage

**Test: Monitor memory during operations**
```python
import psutil
import os

def measure_memory():
    process = psutil.Process(os.getpid())
    return process.memory_info().rss / 1024 / 1024  # MB

print("Initial memory:", measure_memory(), "MB")

# Run operations and measure memory
# ... operations ...

print("Peak memory:", measure_memory(), "MB")
```
Expected: Memory usage remains reasonable (< 2GB for typical operations)

## Phase 9: Error Handling Testing

### 9.1 Invalid Input Handling

**Test: Invalid binary path**
```bash
curl -X POST http://127.0.0.1:5000/api/active-re/plan \
  -H "Content-Type: application/json" \
  -d '{"binary_path": "", "analysis_goal": "test"}'
```
Expected: Returns 400 error with descriptive message

**Test: Missing required fields**
```bash
curl -X POST http://127.0.0.1:5000/api/orchestrator/plan \
  -H "Content-Type: application/json" \
  -d '{}'
```
Expected: Returns 400 error

**Test: Invalid job ID**
```bash
curl http://127.0.0.1:5000/api/orchestrator/tasks/invalid-job-id
```
Expected: Returns 404 error

### 9.2 Service Unavailability

**Test: Docker container not running**
- Stop the Active RE container
- Run Active RE API calls
Expected: Graceful error handling with informative messages

**Test: LLM service unavailable**
- Stop Ollama
- Run RAG search
Expected: Fallback behavior or clear error message

## Phase 10: Direct Component Testing (Non-API)

### 10.1 Python Unit Tests

**Test: ActiveRESandbox class**
```python
import unittest
from core.active_re_service import ActiveRESandbox

class TestActiveRESandbox(unittest.TestCase):
    def setUp(self):
        self.sandbox = ActiveRESandbox()
    
    def test_initialization(self):
        self.assertIsNotNone(self.sandbox.docker_client)
        self.assertEqual(self.sandbox.sandbox_image, "reaa/active-re:latest")
    
    def test_container_name_generation(self):
        job_id = "test-job"
        self.sandbox.start_sandbox(job_id)
        self.assertIn("reaa-active-re", self.sandbox.container_name)
        self.assertIn(job_id, self.sandbox.container_name)

if __name__ == "__main__":
    unittest.main()
```

**Test: FridaInstrumentation class**
```python
import unittest
from core.frida_instrumentation import FridaInstrumentation

class TestFridaInstrumentation(unittest.TestCase):
    def setUp(self):
        self.frida = FridaInstrumentation()
    
    def test_availability(self):
        result = self.frida.is_available()
        self.assertIsInstance(result, bool)
    
    def test_script_template(self):
        from core.frida_instrumentation import FridaScriptTemplates
        script = FridaScriptTemplates.api_call_tracing()
        self.assertIn("Interceptor", script)
        self.assertIn("send", script)

if __name__ == "__main__":
    unittest.main()
```

**Test: AngrBridge class**
```python
import unittest
from core.angr_bridge import AngrBridge

class TestAngrBridge(unittest.TestCase):
    def setUp(self):
        self.angr = AngrBridge()
    
    def test_availability(self):
        result = self.angr.is_available()
        self.assertIsInstance(result, bool)
    
    def test_initialization(self):
        self.assertIsNotNone(self.angr.project)

if __name__ == "__main__":
    unittest.main()
```

**Test: PwndbgBridge class**
```python
import unittest
from core.pwndbg_bridge import PwndbgBridge

class TestPwndbgBridge(unittest.TestCase):
    def setUp(self):
        self.pwndbg = PwndbgBridge()
    
    def test_initialization(self):
        self.assertIsNotNone(self.pwndbg.gdb_path)
        self.assertEqual(self.pwndbg.gdb_path, "/usr/bin/gdb")

if __name__ == "__main__":
    unittest.main()
```

### 10.2 Integration Tests (Python)

**Test: Complete Active RE workflow**
```python
import unittest
from core.active_re_service import ActiveREService
from core.frida_instrumentation import get_frida
from core.angr_bridge import get_angr
from core.pwndbg_bridge import get_pwndbg

class TestActiveREWorkflow(unittest.TestCase):
    def setUp(self):
        self.service = ActiveREService()
        self.frida = get_frida()
        self.angr = get_angr()
        self.pwndbg = get_pwndbg()
    
    def test_service_initialization(self):
        self.assertIsNotNone(self.service.sandbox)
    
    def test_frida_integration(self):
        if self.frida.is_available():
            script = "Interceptor.attach(Module.findExportByName(null, 'open'), {onEnter: function(args) { send(args[0]); }});"
            result = self.frida.load_script(script)
            self.assertTrue(result)
    
    def test_angr_integration(self):
        if self.angr.is_available():
            result = self.angr.is_available()
            self.assertTrue(result)

if __name__ == "__main__":
    unittest.main()
```

### 10.3 Frida Script Testing

**Test: API tracing script execution**
```javascript
// Save as test_api_trace.js
var api_calls = [];

Interceptor.attach(Module.findExportByName(null, "open"), {
    onEnter: function(args) {
        send({type: "api_call", name: "open", args: args[0].readCString()});
    }
});

send({type: "status", message: "Test script loaded"});
```

Run with Frida CLI:
```bash
frida -l test_api_trace.js -f /bin/ls --no-pause
```
Expected: Output showing API calls being intercepted

**Test: Memory tracking script**
```javascript
// Save as test_memory.js
Interceptor.attach(Module.findExportByName(null, "malloc"), {
    onEnter: function(args) {
        this.size = args[0].toInt32();
    },
    onLeave: function(retval) {
        send({type: "malloc", size: this.size, address: retval.toString()});
    }
});

send({type: "status", message: "Memory tracking loaded"});
```

Run with Frida:
```bash
frida -l test_memory.js -p <PID>
```
Expected: Output showing memory allocations

### 10.4 Docker Container Testing

**Test: Container health check**
```bash
# Check container status
docker inspect reaa-active-re | jq '.[0].State.Health'

# Check resource limits
docker inspect reaa-active-re | jq '.[0].HostConfig.Memory'
docker inspect reaa-active-re | jq '.[0].HostConfig.NanoCpus'

# Check network isolation
docker network inspect bridge | jq '.[0].Containers'
```

**Test: Container file system**
```bash
# List installed packages
docker exec reaa-active-re dpkg -l | grep -E "(frida|angr|gdb)"

# Check Python modules
docker exec reaa-active-re python3 -c "import frida, angr; print('OK')"

# Check tool availability
docker exec reaa-active-re which gdb
docker exec reaa-active-re which strace
docker exec reaa-active-re which ltrace
```

**Test: Container isolation**
```bash
# Test network access (should fail if isolated)
docker exec reaa-active-re ping -c 1 google.com

# Test host access (should fail)
docker exec reaa-active-re cat /host/etc/passwd

# Test privilege escalation (should fail)
docker exec reaa-active-re whoami
```

### 10.5 Vector Database Testing

**Test: ChromaDB operations directly**
```python
import chromadb
from chromadb.utils import embedding_functions

# Initialize client
client = chromadb.PersistentClient(path="./test_vector_db")

# Create collection
collection = client.create_collection("test_collection")

# Add documents
collection.add(
    documents=["Test document 1", "Test document 2"],
    metadatas=[{"source": "test"}, {"source": "test"}],
    ids=["doc1", "doc2"]
)

# Query documents
results = collection.query(
    query_texts=["test"],
    n_results=1
)

print("Query results:", results)
assert len(results["documents"][0]) > 0

# Delete collection
client.delete_collection("test_collection")
print("ChromaDB test passed")
```

### 10.6 LLM Client Testing

**Test: LLM client connection**
```python
from core.llm_client import LLMClient

client = LLMClient(
    model="llama3.2:3b",
    api_base="http://localhost:11434/v1"
)

# Test simple completion
messages = [{"role": "user", "content": "Say hello"}]
response = client.completion(messages)
print("LLM response:", response)
assert len(response) > 0

# Test structured output
from core.llm_models import VariableRename
structured = client.completion_structured(
    messages=[{"role": "user", "content": "Rename variable x to result"}],
    output_type=VariableRename
)
print("Structured output:", structured)
assert structured.new_name is not None
```

### 10.7 Data Schema Testing

**Test: Pydantic models validation**
```python
from core.data_schema import ExecutionTrace, MemorySnapshot, NetworkEvent
from datetime import datetime

# Test ExecutionTrace
trace = ExecutionTrace(
    timestamp=datetime.utcnow().isoformat(),
    event_type="api_call",
    process_id=1234,
    function_name="main"
)
print("ExecutionTrace valid:", trace)

# Test MemorySnapshot
snapshot = MemorySnapshot(
    timestamp=datetime.utcnow().isoformat(),
    process_id=1234,
    base_address="0x400000",
    size=4096,
    permissions="rwx"
)
print("MemorySnapshot valid:", snapshot)

# Test NetworkEvent
event = NetworkEvent(
    timestamp=datetime.utcnow().isoformat(),
    process_id=1234,
    source_ip="192.168.1.1",
    source_port=12345,
    destination_ip="192.168.1.2",
    destination_port=80,
    protocol="tcp",
    direction="outbound",
    size=1024
)
print("NetworkEvent valid:", event)
```

### 10.8 Monitoring Modules Testing

**Test: ProcessMonitor with mock data**
```python
import unittest
from core.monitoring import ProcessMonitor
import psutil

class TestProcessMonitor(unittest.TestCase):
    def setUp(self):
        self.monitor = ProcessMonitor()
    
    def test_get_process_tree(self):
        tree = self.monitor.get_process_tree()
        self.assertIsInstance(tree, list)
        self.assertGreater(len(tree), 0)
    
    def test_get_environment_vars(self):
        vars = self.monitor.get_environment_vars(os.getpid())
        self.assertIsInstance(vars, dict)
        self.assertIn("PATH", vars)

if __name__ == "__main__":
    unittest.main()
```

**Test: MemoryMonitor with mock data**
```python
import unittest
from core.monitoring import MemoryMonitor

class TestMemoryMonitor(unittest.TestCase):
    def setUp(self):
        self.monitor = MemoryMonitor()
    
    def test_take_snapshot(self):
        snapshot = self.monitor.take_snapshot(os.getpid())
        self.assertIsNotNone(snapshot)
        self.assertIn("rss", snapshot)
        self.assertIn("vms", snapshot)
    
    def test_get_memory_stats(self):
        stats = self.monitor.get_memory_stats(os.getpid())
        self.assertIsNotNone(stats)
        self.assertIn("basic", stats)
        self.assertIn("extended", stats)

if __name__ == "__main__":
    unittest.main()
```

### 10.9 File System Operations Testing

**Test: DataStorage operations**
```python
import unittest
import tempfile
import shutil
from core.data_schema import DataStorage, ExecutionTrace
from datetime import datetime

class TestDataStorage(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.storage = DataStorage()
        self.storage.data_dir = Path(self.temp_dir)
        self.storage.ensure_directories()
    
    def tearDown(self):
        shutil.rmtree(self.temp_dir)
    
    def test_save_execution_trace(self):
        trace = ExecutionTrace(
            timestamp=datetime.utcnow().isoformat(),
            event_type="test",
            process_id=1234
        )
        path = self.storage.save_execution_trace("test-job", trace)
        self.assertTrue(len(path) > 0)
        self.assertTrue(Path(path).exists())
    
    def test_get_job_artifacts(self):
        artifacts = self.storage.get_job_artifacts("test-job")
        self.assertIsInstance(artifacts, dict)

if __name__ == "__main__":
    unittest.main()
```

### 10.10 End-to-End Workflow Testing

**Test: Complete analysis workflow script**
```python
#!/usr/bin/env python3
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

def test_complete_workflow():
    print("Testing complete Active RE workflow...")
    
    # Step 1: Initialize components
    from core.active_re_service import ActiveREService
    from core.frida_instrumentation import get_frida
    from core.angr_bridge import get_angr
    from core.pwndbg_bridge import get_pwndbg
    from core.monitoring import ProcessMonitor, MemoryMonitor
    from core.vector_store import get_vector_store
    from core.knowledge_base import get_knowledge_base
    from core.retriever import get_retriever
    
    print("Step 1: Initializing components...")
    service = ActiveREService()
    frida = get_frida()
    angr = get_angr()
    pwndbg = get_pwndbg()
    process_monitor = ProcessMonitor()
    memory_monitor = MemoryMonitor()
    vector_store = get_vector_store()
    knowledge_base = get_knowledge_base()
    retriever = get_retriever()
    
    # Step 2: Test component availability
    print("Step 2: Checking component availability...")
    print(f"  Frida available: {frida.is_available()}")
    print(f"  angr available: {angr.is_available()}")
    print(f"  Vector store available: {vector_store.is_available()}")
    print(f"  Retriever available: {retriever.is_available()}")
    
    # Step 3: Test monitoring
    print("Step 3: Testing monitoring...")
    process_tree = process_monitor.get_process_tree()
    print(f"  Process tree size: {len(process_tree)}")
    
    memory_snapshot = memory_monitor.take_snapshot(os.getpid())
    print(f"  Memory snapshot RSS: {memory_snapshot['rss']}")
    
    # Step 4: Test RAG system
    print("Step 4: Testing RAG system...")
    if vector_store.is_available():
        vector_store.create_collection("test_workflow")
        vector_store.add_documents(
            collection_name="test_workflow",
            documents=["Test document for workflow"]
        )
        results = vector_store.query(
            collection_name="test_workflow",
            query_text="test",
            n_results=1
        )
        print(f"  Query results: {len(results.get('documents', [[]])[0])}")
        vector_store.delete_collection("test_workflow")
    
    # Step 5: Test data storage
    print("Step 5: Testing data storage...")
    from core.data_schema import DataStorage, ExecutionTrace
    storage = DataStorage()
    trace = ExecutionTrace(
        timestamp=datetime.utcnow().isoformat(),
        event_type="workflow_test",
        process_id=os.getpid()
    )
    path = storage.save_execution_trace("workflow-test", trace)
    print(f"  Saved trace to: {path}")
    
    print("\nComplete workflow test finished successfully!")

if __name__ == "__main__":
    test_complete_workflow()
```

Run with:
```bash
python test_complete_workflow.py
```

## Phase 11: Security Testing

### 10.1 Sandbox Isolation

**Test: Container cannot access host**
```bash
docker exec reaa-active-re ls /
docker exec reaa-active-re cat /etc/passwd
```
Expected: Limited access, no sensitive host information exposed

**Test: Network isolation**
```bash
docker exec reaa-active-re ping google.com
```
Expected: Fails if network isolation is enabled

### 10.2 Input Validation

**Test: Path traversal attempts**
```bash
curl -X POST http://127.0.0.1:5000/api/active-re/plan \
  -H "Content-Type: application/json" \
  -d '{"binary_path": "../../../etc/passwd", "analysis_goal": "test"}'
```
Expected: Rejected or sanitized

## Test Automation Script

Create a test script `run_tests.py`:

```python
import requests
import json
import sys

BASE_URL = "http://127.0.0.1:5000"

def test_active_re_plan():
    response = requests.post(
        f"{BASE_URL}/api/active-re/plan",
        json={
            "binary_path": "/tmp/test.exe",
            "analysis_goal": "vulnerability detection"
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert "mode" in data
    print("PASS: Active RE plan")

def test_orchestrator_plan():
    response = requests.post(
        f"{BASE_URL}/api/orchestrator/plan",
        json={
            "binary_path": "/tmp/test.exe",
            "user_request": "Analyze for vulnerabilities"
        }
    )
    assert response.status_code == 200
    print("PASS: Orchestrator plan")

def test_rag_search():
    response = requests.post(
        f"{BASE_URL}/api/rag/search",
        json={"query": "test", "n_results": 5}
    )
    assert response.status_code == 200
    print("PASS: RAG search")

def run_all_tests():
    tests = [
        test_active_re_plan,
        test_orchestrator_plan,
        test_rag_search
    ]
    
    failed = []
    for test in tests:
        try:
            test()
        except Exception as e:
            print(f"FAIL: {test.__name__} - {e}")
            failed.append(test.__name__)
    
    if failed:
        print(f"\nFailed tests: {len(failed)}")
        sys.exit(1)
    else:
        print("\nAll tests passed!")

if __name__ == "__main__":
    run_all_tests()
```

Run with:
```bash
python run_tests.py
```

## Test Checklist

- [ ] Docker sandbox builds and starts successfully
- [ ] Active RE service starts without errors
- [ ] Frida instrumentation loads scripts
- [ ] angr symbolic execution initializes
- [ ] pwndbg debugging bridge connects
- [ ] All monitoring modules function correctly
- [ ] Vector store creates and queries collections
- [ ] Knowledge base indexes and retrieves data
- [ ] RAG system returns relevant context
- [ ] ActiveREAgent plans and executes strategies
- [ ] OrchestratorAgent coordinates agents
- [ ] ReportAgent generates comprehensive reports
- [ ] All API endpoints respond correctly
- [ ] Error handling works as expected
- [ ] Sandbox isolation is maintained
- [ ] Performance benchmarks are met

## Continuous Integration

For automated testing in CI/CD:

1. Create `.github/workflows/test.yml`
2. Run tests on every push
3. Test on multiple Python versions (3.10, 3.11, 3.12)
4. Test on multiple OS platforms if possible
5. Report test results to GitHub Actions

## Troubleshooting

**Docker build fails:**
- Check Docker daemon is running
- Verify base image is available
- Check network connectivity

**API returns 500 errors:**
- Check logs in webui terminal
- Verify environment variables are set
- Check if required services (Redis, Ghidra API) are running

**RAG search returns no results:**
- Verify vector store is initialized
- Check if documents are indexed
- Verify embedding model is available

**Orchestrator approval stuck:**
- Check if human approval is required
- Manually approve via API
- Check task status endpoint

**Memory leaks detected:**
- Monitor memory usage during long-running operations
- Restart services periodically
- Check for unclosed connections
