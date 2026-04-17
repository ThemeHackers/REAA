# REAA - Reverse Engineering Analysis Assistant

AI-powered reverse engineering platform combining Ghidra, Radare2, and advanced analysis tools for malware analysis and security research.

## 🚀 Features

### Core Analysis
- **Ghidra 12.0.4 Integration**: Latest Ghidra with PyGhidra support
- **Decompilation**: FlatDecompilerAPI for reliable decompilation in headless mode
- **Enhanced Function Analysis**: Call graphs, control flow, and execution paths
- **Memory Layout Analysis**: Memory sections with permissions visualization
- **Code Coverage**: Decompilation and address space coverage metrics

### AI Integration
- **Ghidra Assistant**: AI-powered reverse engineering analysis
- **Security Agent**: Specialized vulnerability detection
- **Natural Language Query**: Search analysis results using natural language
- **MCP Protocol**: Model Context Protocol for AI tool integration

### Visualization Tools
- **Function Graph**: Visualize call relationships and dependencies
- **Control Flow**: Analyze execution paths and basic blocks
- **Memory Layout**: View memory sections and permissions
- **Timeline View**: Track analysis progress and stages

### Additional Tools
- **Radare2 Integration**: Command-line reverse engineering
- **Transaction Support**: Safe program modifications
- **Analysis Properties**: Customizable analysis parameters
- **Program Info Management**: Metadata and documentation

### Active Reverse Engineering (NEW)
- **Dynamic Execution**: Run binaries in isolated Docker sandbox
- **Frida Instrumentation**: Runtime API call and memory monitoring
- **angr Symbolic Execution**: Path exploration and constraint solving
- **pwndbg Integration**: Enhanced debugging with heap analysis
- **Multi-Agent System**: Orchestrated analysis with AI agents
- **RAG System**: Context-aware retrieval from analysis history

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   Windows Native (GPU)                      │
│  ┌─────────────┐      ┌──────────────────┐                  │
│  │   Ollama    │      │ llm4decompile    │                  │
│  │ (llama3.2)  │      │    (1.3B-v2)     │                  │
│  │  RTX 2060   │      │    RTX 2060      │                  │
│  └─────────────┘      └──────────────────┘                  │
└─────────────────────────────────────────────────────────────┘
        │                         │
        │ http://localhost:11434   │ Direct PyTorch
        │                         │
        └──────────┬──────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────────────────┐
│                    Docker (Ghidra API)                      │
│  ┌─────────────┐      ┌─────────────┐      ┌──────────────┐ │
│  │   WebUI     │─────▶│  FastAPI    │◀─────│  Celery     │ │
│  │  (Flask)    │      │   (REST)    │      │  Worker      │ │
│  │             │      │             │      └──────────────┘ │
│  │  + Agents   │      │             │                     │
│  └─────────────┘      └─────────────┘                     │
│       │                    │                                 │
│       │                    │                                 │
│       ▼                    ▼                                 │
│  ┌─────────────┐      ┌─────────────┐                     │
│  │   Redis     │      │  Radare2    │                     │
│  │  (Broker)   │      │  (CLI)      │                     │
│  └─────────────┘      └─────────────┘                     │
└─────────────────────────────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────────────────────────────┐
│              Active RE Docker Sandbox (NEW)                 │
│  ┌─────────────┐      ┌─────────────┐      ┌──────────────┐ │
│  │   Frida     │      │    angr     │      │   pwndbg     │ │
│  │ Instrument  │      │  Symbolic   │      │  Enhanced    │ │
│  └─────────────┘      └─────────────┘      │  Debugging   │ │
│                                             └──────────────┘ │
│  ┌─────────────┐      ┌─────────────┐                      │
│  │   Procmon   │      │  Wireshark  │                      │
│  │  Monitor    │      │  Capture    │                      │
│  └─────────────┘      └─────────────┘                      │
│  ┌───────────────────────────────────────────────────────┐ │
│  │              Vector Database (ChromaDB)                 │ │
│  │              RAG System + Knowledge Base                │ │
│  └───────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

## 📦 Installation

### Prerequisites
- Docker and Docker Compose
- At least 4GB RAM (8GB recommended for large binaries)
- Python 3.10+ (for local development)

### GPU Requirements (for LLM-based decompilation)

**For llm4decompile integration:**
- **VRAM**: Minimum 4GB (6GB+ recommended)
- **GPU**: NVIDIA GPU with CUDA support (CUDA 11.8+ or 12.x)
- **Compatible GPUs**: RTX series (2060+, 3060+, 4060+), GTX series (1660+, 1060+), Tesla series
- **AMD GPUs**: Not officially supported (ROCm may work but not recommended)

**Performance:**
- **CPU**: ~30 seconds per file (not recommended for production)
- **GPU**: ~3-5 seconds per file (8-10x faster)

**Installation:**
```bash
# Check Python version
python --version # Should be 3.14.x or 3.14.3

# Create virtual environment
python -m venv .venv
.venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# For GPU support, install PyTorch with CUDA
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu126

# Verify GPU availability
python -c "import torch; print('CUDA available:', torch.cuda.is_available())"
```

### Windows Native AI Models Setup

**Ollama Models (for Chat & AI):**

Available models for general AI assistance:
- **qwen3-vl:30b** - 30B parameters, vision-language model (requires 16GB+ VRAM)
- **qwen3-vl:8b** - 8B parameters, vision-language model (requires 6GB+ VRAM)
- **qwen3-vl:4b** - 4B parameters, vision-language model (requires 4GB+ VRAM)
- **qwen3.5:27b** - 27B parameters, general purpose (requires 16GB+ VRAM)
- **qwen3.5:9b** - 9B parameters, general purpose (requires 6GB+ VRAM)
- **qwen3.5:4b** - 4B parameters, general purpose (requires 4GB+ VRAM)
- **llama3.2:3b** - 3B parameters, general purpose (recommended for RTX 2060)

**Ollama Setup (llama3.2:3b):**
```bash
# Install Ollama for Windows
irm https://ollama.com/install.ps1 | iex

# Start Ollama server
ollama serve

# Download llama3.2:3b model
ollama pull llama3.2:3b

# To use other models, replace with:
# ollama pull qwen3.5:4b
# ollama pull qwen3-vl:4b

# Verify
Invoke-RestMethod -Uri "http://localhost:11434/api/tags"
# or
curl http://localhost:11434/api/tags
```

**Hugging Face Authentication (Recommended):**

Some models require Hugging Face authentication for faster downloads and access to restricted models. Installing HF CLI and logging in will:

- **Increase download speed** - Higher rate limits for authenticated users
- **Access restricted models** - Some models are only available to authenticated users
- **Avoid rate limiting** - Prevent download throttling

```bash
# Install Hugging Face CLI for Windows
powershell -ExecutionPolicy ByPass -c "irm https://hf.co/cli/install.ps1 | iex"

# Login to Hugging Face
hf auth login

# Follow the prompts to:
# 1. Open https://huggingface.co/settings/tokens
# 2. Create a new access token (select "Read" permission)
# 3. Paste the token when prompted
# 4. Add token as git credential (optional but recommended)

# Verify login
hf auth whoami
```

**Note:** Without HF_TOKEN, you may encounter:
- Slower model downloads
- Rate limiting errors
- Inability to access certain restricted models

**LLM4Decompile Models (for Pseudocode Refinement):**

Available models for decompilation refinement:
| Model | Size | Re-executability | VRAM Required |
|-------|------|------------------|---------------|
| llm4decompile-1.3b-v1.5 | 1.3B | 27.3% | 4GB+ |
| llm4decompile-6.7b-v1.5 | 6.7B | 45.4% | 8GB+ |
| llm4decompile-1.3b-v2 | 1.3B | 46.0% | 4GB+ |
| llm4decompile-6.7b-v2 | 6.7B | 52.7% | 8GB+ |
| llm4decompile-9b-v2 | 9B | 64.9% | 12GB+ |
| llm4decompile-22b-v2 | 22B | 63.6% | 24GB+ |

**Note:** Re-executability indicates the percentage of refined code that can be successfully recompiled. Higher values indicate better decompilation accuracy. For RTX 2060 (6GB VRAM), recommended models are:
- **Ollama**: llama3.2:3b or qwen3.5:4b
- **LLM4Decompile**: llm4decompile-1.3b-v2 or llm4decompile-6.7b-v2

### Quick Start

1. **Clone repository**:
```bash
git clone https://github.com/Themehackers/REAA
cd REAA
```

2. **Configure environment**:
```bash
cp .env.example .env
# Edit .env with your settings
```

3. **Start AI models (Windows Native)**:
```bash
# Terminal 1: Start Ollama
ollama serve

# Terminal 2: (Optional) Verify Ollama
curl http://localhost:11434/api/tags
```

4. **Start Docker services**:
```bash
# Terminal 3: Start & Build Ghidra API infrastructure
docker-compose build
docker-compose up -d
```

5. **Run app.py**

```
python webui/app.py
```

6. **Access WebUI**:
```
http://127.0.0.1:5000
```


## 🔧 Configuration

### Environment Variables

```bash
API_KEY=ollama
API_BASE=http://localhost:11434/v1
MODEL_NAME=llama3.2:3b
OLLAMA_MAX_TOKENS=4096
OLLAMA_TEMPERATURE=0.7
LLM4DECOMPILE_MODEL_PATH=LLM4Binary/llm4decompile-1.3b-v2
LLM4DECOMPILE_DEVICE=auto
LLM4DECOMPILE_DTYPE=float16
LLM4DECOMPILE_MAX_MEMORY={0: "6GB"}
LLM4DECOMPILE_QUANTIZATION=
LLM4DECOMPILE_MAX_NEW_TOKENS=2048
GHIDRA_HOME=/opt/ghidra
GHIDRA_BIN=/opt/ghidra/support/analyzeHeadless
GHIDRA_SCRIPTS=/app/ghidra_scripts
GHIDRA_VERSION=12.0.4
DATA_DIR=/data/ghidra_projects
MAX_UPLOAD_SIZE=209715200
API_TITLE=Ghidra Headless REST API
API_VERSION=2.0.0
REDIS_URL=redis://localhost:6379/0
CELERY_BROKER_URL=redis://localhost:6379/0
CELERY_RESULT_BACKEND=redis://localhost:6379/0
CELERY_TASK_TIMEOUT=1800
LOG_LEVEL=INFO
ADMIN_USERNAME='It's up to you'
ADMIN_EMAIL='It's up to you'
ADMIN_PASSWORD='It's up to you'

ACTIVE_RE_ENABLED=true
ACTIVE_RE_SANDBOX_IMAGE=reaa/active-re:latest
ACTIVE_RE_NETWORK_MODE=bridge
ACTIVE_RE_NETWORK_ISOLATED=true
ACTIVE_RE_TIMEOUT=300
ACTIVE_RE_MAX_MEMORY=2GB
ACTIVE_RE_MAX_CPU=2.0

FRIDA_SCRIPTS_DIR=/app/frida_scripts
FRIDA_DEVICE_TIMEOUT=60

ANGR_ENABLED=true
ANGR_LLM_MODEL=llama3.2:3b
ANGR_LLM_API_BASE=http://localhost:11434/v1
ANGR_LLM_API_KEY=
ANGR_SYMBOLIC_EXECUTION_TIMEOUT=300

PWNBG_ENABLED=true
PWNBG_GDB_PATH=/usr/bin/gdb
PWNBG_HEAP_ANALYSIS_ENABLED=true
PWNBG_MEMORY_VISUALIZATION_ENABLED=true

VECTOR_DB_TYPE=chromadb
VECTOR_DB_PATH=./data/vector_db
EMBEDDING_MODEL=sentence-transformers/all-MiniLM-L6-v2
RAG_TOP_K=5
RAG_SIMILARITY_THRESHOLD=0.7

ORCHESTRATOR_ENABLED=true
HUMAN_APPROVAL_REQUIRED=true
AGENT_MAX_TURNS=10
AGENT_TIMEOUT=120
```

## 📊 Analysis Output

### Generated Files

Each analysis generates comprehensive artifacts:

- **functions.json**: Function metadata with enhanced information
- **xrefs.json**: Cross-references and dependencies
- **imports.json**: Imported symbols
- **strings.json**: Extracted strings
- **pseudocode/**: Decompiled function code
- **function_graph.json**: Call relationship visualization
- **memory_layout.json**: Memory sections and permissions
- **control_flow.json**: Execution paths and basic blocks
- **coverage.json**: Analysis coverage metrics
- **timeline.json**: Analysis progress tracking

## 🌐 WebUI Features

### Main Interface
- **File Upload**: Drag-and-drop binary analysis
- **Chat Interface**: AI-powered analysis assistance
- **Job Management**: Track analysis progress
- **Results Visualization**: Interactive analysis results

### Tools
- **Ghidra Terminal**: Direct Ghidra command access
- **Radare2 Terminal**: Radare2 CLI integration
- **Security Analysis**: Vulnerability detection
- **Code Review**: AI-assisted code review

### Visualization
- **Timeline View**: Analysis progress timeline
- **Call Graph**: Interactive function call visualization
- **Memory Layout**: Memory sections and permissions
- **Control Flow**: Execution paths and basic blocks

### Collaboration
- **Remote Collaboration**: Share analysis sessions
- **Real-time Sync**: Live updates across users
- **Job Sharing**: Share decompilation results

### Pseudocode Refinement
- **Refine All**: Batch refine all pseudocode files
- **Selective Refine**: Choose specific files to refine
- **LLM Integration**: Uses llm4decompile model

### Active Reverse Engineering (NEW)
- **Execution Planning**: Plan dynamic analysis strategies
- **Sandbox Execution**: Run binaries in isolated Docker containers
- **Frida Scripts**: Use pre-defined or custom Frida instrumentation
- **Symbolic Execution**: Explore execution paths with angr
- **Enhanced Debugging**: Use pwndbg for heap analysis
- **Multi-Agent Coordination**: Orchestrated analysis with AI agents
- **Report Generation**: Comprehensive security reports
- **RAG Retrieval**: Search analysis history for context

### Export
- **Export Results**: Download analysis artifacts
- **Multiple Formats**: JSON, text, and structured exports

## 🔌 API Endpoints

### Authentication
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - User login
- `POST /api/auth/logout` - User logout
- `GET /api/auth/me` - Get current user info

### Analysis
- `POST /upload` - Upload binary for analysis
- `GET /jobs` - List all jobs
- `GET /status/{job_id}` - Get job status
- `GET /api/jobs` - List jobs (API)
- `GET /api/jobs/{job_id}` - Get job details
- `DELETE /api/jobs/{job_id}` - Delete job
- `GET /api/jobs/{job_id}/download` - Download job artifacts
- `POST /api/jobs/cleanup` - Clean up old jobs

### Chat & AI
- `POST /chat` - Send chat message
- `GET /chat/history/{job_id}` - Get chat history
- `DELETE /chat/history/{job_id}` - Clear chat history

### Security Analysis
- `POST /security/analyze` - Analyze security vulnerabilities
- `GET /security/report/{job_id}` - Get security report
- `DELETE /security/history/{job_id}` - Clear security history
- `POST /security/scan` - Scan for vulnerabilities

### Pseudocode Refinement
- `GET /results/{job_id}/function/{addr}/refine` - Refine single function
- `POST /api/jobs/{job_id}/refine/batch` - Batch refine all functions
- `GET /api/jobs/{job_id}/pseudocode/files` - List pseudocode files
- `POST /api/jobs/{job_id}/refine/selective` - Selective refinement

### Results & Visualization
- `GET /api/jobs/{job_id}/memory` - Get memory layout
- `GET /api/jobs/{job_id}/callgraph` - Get call graph
- `GET /api/jobs/{job_id}/controlflow/{function_address}` - Get control flow

### Radare2 Integration
- `GET /api/r2/status` - Radare2 status
- `POST /api/r2/analyze` - Analyze binary with R2
- `POST /api/r2/command` - Execute R2 command
- `POST /api/r2/load` - Load binary in R2
- `GET /api/r2/functions` - List functions
- `GET /api/r2/strings` - List strings
- `GET /api/r2/imports` - List imports
- `POST /api/r2/autonomous` - Autonomous analysis
- `GET /api/r2/summary` - Get analysis summary
- `GET/POST /api/r2/boundaries` - Get/set boundaries
- `GET/POST /api/r2/asm/config` - Get/set ASM config
- `POST /api/r2/asm/preset` - Set ASM preset
- `POST /api/r2/disasm/function` - Disassemble function
- `POST /api/r2/disasm/range` - Disassemble range
- `POST /api/r2/disasm/graph` - Get disassembly graph
- `POST /api/asm/analyze` - Analyze assembly

### System & Monitoring
- `GET /api/system/status` - System status
- `GET /api/docker/status` - Docker status
- `GET /api/docker/logs/{container_name}` - Docker container logs
- `GET /gpu/status` - GPU status
- `GET /gpu/detailed` - Detailed GPU info
- `GET /api/remote/health` - Remote collaboration health

### Active Reverse Engineering (NEW)
- `POST /api/active-re/plan` - Plan Active RE execution strategy
- `POST /api/active-re/execute` - Execute binary with Frida instrumentation
- `POST /api/active-re/monitor` - Monitor binary execution
- `POST /api/active-re/chat` - Chat with Active RE agent
- `POST /api/orchestrator/plan` - Plan analysis strategy with orchestrator
- `POST /api/orchestrator/execute` - Execute orchestrated analysis
- `GET /api/orchestrator/approvals` - Get pending approval requests
- `POST /api/orchestrator/approve` - Approve or reject operation
- `GET /api/orchestrator/tasks` - Get all orchestrator tasks
- `GET /api/orchestrator/tasks/{job_id}` - Get specific task status
- `POST /api/report/generate` - Generate comprehensive security report
- `POST /api/rag/search` - Search RAG knowledge base
- `POST /api/rag/similar-functions` - Find similar functions
- `POST /api/rag/vulnerabilities` - Search vulnerability patterns

## ️ Troubleshooting

### AI Model Issues

**Ollama GPU Issues:**
```bash
# Check if GPU is detected
curl http://localhost:11434/api/tags

# If GPU not detected, ensure:
# 1. NVIDIA drivers are installed
# 2. CUDA is properly configured
# 3. Ollama is running with GPU support
```

**PyTorch GPU Issues:**
```bash
# Check CUDA availability
python -c "import torch; print(torch.cuda.is_available())"

# Check GPU name
python -c "import torch; print(torch.cuda.get_device_name(0))"

# Reinstall PyTorch if needed
pip uninstall torch torchvision torchaudio
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu124
```

**Model Download Issues:**
```bash
# For Ollama, try:
ollama pull llama3.2:3b --verbose

# For llm4decompile, check:
# 1. Internet connection
# 2. Hugging Face access
# 3. Disk space (model is ~5GB)
```


### Celery Worker Issues
```bash
# Check worker status
docker-compose logs celery-worker

# Restart worker
docker-compose restart celery-worker
```

## � Active Reverse Engineering Usage

### Starting Active RE Analysis

1. **Build the Active RE Docker image**:
```bash
cd docker/active-re
docker-compose build
```

2. **Start the Active RE sandbox**:
```bash
docker-compose up -d
```

3. **Plan an execution strategy**:
```bash
curl -X POST http://127.0.0.1:5000/api/active-re/plan \
  -H "Content-Type: application/json" \
  -d '{
    "binary_path": "/path/to/binary.exe",
    "analysis_goal": "vulnerability detection",
    "binary_type": "exe"
  }'
```

4. **Execute with Frida instrumentation**:
```bash
curl -X POST http://127.0.0.1:5000/api/active-re/execute \
  -H "Content-Type: application/json" \
  -d '{
    "job_id": "your-job-id",
    "binary_path": "/path/to/binary.exe"
  }'
```

5. **Monitor execution**:
```bash
curl -X POST http://127.0.0.1:5000/api/active-re/monitor \
  -H "Content-Type: application/json" \
  -d '{
    "job_id": "your-job-id",
    "duration": 30
  }'
```

### Using the Orchestrator

The orchestrator agent coordinates multiple analysis tools:

```bash
# Plan analysis strategy
curl -X POST http://127.0.0.1:5000/api/orchestrator/plan \
  -H "Content-Type: application/json" \
  -d '{
    "binary_path": "/path/to/binary.exe",
    "user_request": "Perform comprehensive security analysis",
    "binary_type": "exe"
  }'

# Execute orchestrated analysis
curl -X POST http://127.0.0.1:5000/api/orchestrator/execute \
  -H "Content-Type: application/json" \
  -d '{
    "job_id": "your-job-id",
    "binary_path": "/path/to/binary.exe",
    "strategy": {...}
  }'

# Check for pending approvals
curl http://127.0.0.1:5000/api/orchestrator/approvals

# Approve or reject operation
curl -X POST http://127.0.0.1:5000/api/orchestrator/approve \
  -H "Content-Type: application/json" \
  -d '{
    "job_id": "your-job-id",
    "approved": true
  }'
```

### RAG System Usage

Search the knowledge base for similar functions and vulnerabilities:

```bash
# Search for similar functions
curl -X POST http://127.0.0.1:5000/api/rag/similar-functions \
  -H "Content-Type: application/json" \
  -d '{
    "function_code": "int main() { return 0; }",
    "n_results": 5
  }'

# Search for vulnerability patterns
curl -X POST http://127.0.0.1:5000/api/rag/vulnerabilities \
  -H "Content-Type: application/json" \
  -d '{
    "code_snippet": "strcpy(buffer, input)",
    "n_results": 5
  }'
```

### Report Generation

Generate comprehensive security reports:

```bash
curl -X POST http://127.0.0.1:5000/api/report/generate \
  -H "Content-Type: application/json" \
  -d '{
    "job_id": "your-job-id",
    "analysis_results": {...},
    "output_format": "html"
  }'
```

## �📚 Additional Resources

- [Ghidra Documentation](https://ghidra-sre.org/)
- [PyGhidra Documentation](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/PyGhidra/src/main/py/README.md)
- [Radare2 Documentation](https://radare.org/)
- [Celery Documentation](https://docs.celeryproject.org/)

## 🙏 Acknowledgments & Inspirations

This project is inspired by and builds upon the work of several innovative projects in the AI-powered reverse engineering space:

- **[ai-reverse-engineering](https://github.com/biniamf/ai-reverse-engineering)** by biniamf - Pioneering the integration of AI models with reverse engineering workflows
- **[r2dec-js](https://github.com/wargio/r2dec-js)** by wargio - Advanced decompiler implementation for Radare2 with JavaScript-based analysis
- **[LLM4Decompile](https://github.com/albertan017/LLM4Decompile)** by albertan017 - Leveraging Large Language Models for decompilation and pseudocode refinement

These projects have demonstrated the potential of combining traditional reverse engineering tools with modern AI techniques, paving the way for more intelligent and automated analysis workflows. REAA aims to extend these concepts by integrating multiple tools (Ghidra, Radare2) and AI models (Ollama, LLM4Decompile) into a unified platform for comprehensive malware analysis and security research.
