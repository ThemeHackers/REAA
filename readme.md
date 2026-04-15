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

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   Windows Native (GPU)                      │
│  ┌─────────────┐      ┌──────────────────┐                 │
│  │   Ollama    │      │ llm4decompile    │                 │
│  │ (llama3.2)  │      │    (1.3B-v2)     │                 │
│  │  RTX 2060   │      │    RTX 2060      │                 │
│  └─────────────┘      └──────────────────┘                 │
└─────────────────────────────────────────────────────────────┘
        │                         │
        │ http://localhost:11434   │ Direct PyTorch
        │                         │
        └──────────┬──────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────────────────┐
│                    Docker (Ghidra API)                       │
│  ┌─────────────┐      ┌─────────────┐      ┌──────────────┐│
│  │   WebUI     │─────▶│  FastAPI    │◀─────│  Celery      ││
│  │  (Flask)    │      │   (REST)    │      │  Worker      ││
│  └─────────────┘      └─────────────┘      └──────────────┘│
│       │                    │                     │          │
│       │                    │                     ▼          │
│       │                    │              ┌──────────────┐  │
│       │                    │              │   Ghidra     │  │
│       │                    │              │  12.0.4      │  │
│       │                    │              └──────────────┘  │
│       ▼                    ▼                     │          │
│  ┌─────────────┐      ┌─────────────┐             │          │
│  │   Redis     │      │  Radare2    │             │          │
│  │  (Broker)   │      │  (CLI)      │             │          │
│  └─────────────┘      └─────────────┘             │          │
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
# For GPU support, install PyTorch with CUDA
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu124

# Verify GPU availability
python -c "import torch; print('CUDA available:', torch.cuda.is_available())"
```

### Windows Native AI Models Setup

**Ollama Setup (llama3.2:3b):**
```bash
# Install Ollama for Windows
winget install Ollama.Ollama

# Start Ollama server
ollama serve

# Download llama3.2:3b model
ollama pull llama3.2:3b

# Verify
curl http://localhost:11434/api/tags
```

**llm4decompile Setup (1.3B-v2):**
```bash
# Install PyTorch with CUDA
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu124

# Install transformers
pip install transformers>=4.30.0

# Model will auto-download on first use
# Or clone manually:
git clone https://huggingface.co/LLM4Binary/llm4decompile-1.3b-v2
```

### Recommended Models for RTX 2060 (6GB VRAM)

**Primary Models:**
- **Ollama**: llama3.2:3b (2GB) - General AI assistance
- **llm4decompile**: 1.3B-v2 (4-6GB) - Pseudo-code refinement

### Performance Comparison

| Deployment | Speed | GPU Support | Setup Complexity |
|------------|-------|-------------|------------------|
| Ollama Windows Native | Fast | Full | Low |
| llm4decompile CPU | Slow (~30s/file) | No | Medium |
| llm4decompile GPU | Fast (~3s/file) | Full | Medium |

### Benefits of Windows Native Deployment

1. **Maximum GPU Performance**: Direct GPU access without Docker overhead
2. **Faster Inference**: 8-10x speedup for llm4decompile
3. **Simplified Setup**: No Docker GPU configuration needed
4. **Flexibility**: Easy to switch between models
5. **Cost Effective**: No GPU passthrough complexity

### Quick Start

1. **Clone repository**:
```bash
git clone <repository>
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
# Terminal 3: Start Ghidra API infrastructure
docker-compose up -d
```

5. **Access WebUI**:
```
http://127.0.0.1:5000
```

6. **Verify API**:
```bash
curl http://127.0.0.1:8000/health
```

## 🔧 Configuration

### Environment Variables

```bash
# Ghidra Configuration
GHIDRA_HOME=/opt/ghidra
GHIDRA_BIN=/opt/ghidra/support/analyzeHeadless
GHIDRA_SCRIPTS=/app/ghidra_scripts
GHIDRA_VERSION=12.0.4

# Data Storage
DATA_DIR=/data/ghidra_projects
MAX_UPLOAD_SIZE=209715200  # 200MB

# Redis & Celery
REDIS_URL=redis://localhost:6379/0
CELERY_BROKER_URL=redis://localhost:6379/0
CELERY_RESULT_BACKEND=redis://localhost:6379/0
CELERY_TASK_TIMEOUT=1800

# API Configuration
API_TITLE=Ghidra Headless REST API
API_VERSION=2.0.0

# AI Integration
API_KEY=ollama
API_BASE=http://localhost:11434/v1
MODEL_NAME=qwen2.5:3b
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

### Enhanced Function Metadata

Each function includes:
- Basic info: name, address, size, return type
- Parameters: name, type, ordinal
- Calling convention
- Body information: start, end, size
- Call metrics: caller count, called count
- Decompilation excerpt

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

## 🔌 API Endpoints

### Analysis
- `POST /analyze` - Upload binary for analysis
- `POST /analyze_b64` - Upload base64-encoded binary
- `GET /status/{job_id}` - Get job status
- `GET /jobs` - List all jobs

### Results
- `GET /results/{job_id}/functions` - List functions
- `GET /results/{job_id}/function/{addr}/decompile` - Get decompiled code
- `GET /results/{job_id}/xrefs/{addr}` - Get cross-references
- `GET /results/{job_id}/imports` - List imports
- `GET /results/{job_id}/strings` - List strings
- `POST /query` - Natural language search

### Monitoring
- `GET /health` - Health check
- `GET /metrics` - System metrics

### MCP Integration
- `GET /mcp/descriptor` - MCP tool descriptor
- `GET /mcp/tools` - MCP tools definition
- `POST /tools/*` - MCP tool endpoints

## 💻 Development

### Local Development

1. **Install dependencies**:
```bash
pip install -r requirements.txt
```

2. **Install Ghidra 12.0.4** and set `GHIDRA_HOME`

3. **Start Redis**:
```bash
redis-server
```

4. **Start Celery worker**:
```bash
celery -A core.celery_app worker --loglevel=info
```

5. **Start API**:
```bash
uvicorn core.app:app --reload --port 8000
```

6. **Start WebUI**:
```bash
python webui/app.py
```

### Adding Custom Scripts

Add custom Ghidra scripts to `ghidra_scripts/`:

```python
# Example custom script
from ghidra.program.model.listing import FunctionIterator

# Your custom analysis logic
# ...
```

## 🔍 Usage Examples

### Analyze Binary via API
```bash
curl -X POST http://localhost:8000/analyze \
  -F "file=@malware.exe" \
  -F "persist=false"
```

### Natural Language Query
```bash
curl -X POST http://localhost:8000/query \
  -H "Content-Type: application/json" \
  -d '{"query": "Find functions that call malloc"}'
```

### Get Function Graph
```bash
curl http://localhost:8000/results/{job_id}/function_graph
```

## 🛠️ Troubleshooting

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

### Decompiler Not Working
- Ensure Ghidra 12.0.4 is properly installed
- Check PyGhidra installation: `pip install pyghidra`
- Verify script path in `GHIDRA_SCRIPTS`
- Check worker logs for detailed errors

### Celery Worker Issues
```bash
# Check worker status
docker-compose logs celery-worker

# Restart worker
docker-compose restart celery-worker
```

### Memory Issues
- Increase Docker memory limit
- Reduce `MAX_UPLOAD_SIZE`
- Increase system RAM

## 📈 Performance Optimization

### Scaling
- Increase Celery worker count in `docker-compose.yml`
- Use Redis Cluster for high availability
- Implement job queuing strategies

### Caching
- Enable result caching for repeated analyses
- Use CDN for static assets
- Implement database query optimization

## 🔒 Security Considerations

1. **Authentication**: Add API authentication middleware
2. **Rate Limiting**: Implement request rate limiting
3. **File Validation**: Validate uploaded files
4. **Sandboxing**: Isolate analysis environment
5. **TLS**: Enable HTTPS for production
6. **Input Sanitization**: Sanitize all user inputs

## 📝 License

This project is based on the biniamfd/ghidra-headless-rest reference implementation with significant enhancements.

## 🤝 Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📚 Additional Resources

- [Ghidra Documentation](https://ghidra-sre.org/)
- [PyGhidra Documentation](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/PyGhidra/src/main/py/README.md)
- [Radare2 Documentation](https://radare.org/)
- [Celery Documentation](https://docs.celeryproject.org/)

## 🎯 Roadmap

- [ ] Enhanced decompiler integration
- [ ] Binary diffing capabilities
- [ ] Machine learning-based classification
- [ ] Collaborative analysis features
- [ ] Plugin system for custom analyzers
