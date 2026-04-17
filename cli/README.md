# REAA CLI - Command Line Interface

Beautiful CLI tool for interacting with REAA API endpoints using rich library.

## 🚀 Features

- **Beautiful Terminal UI**: Powered by Rich library for stunning terminal output
- **Complete API Coverage**: All API endpoints accessible via CLI
- **Command Groups**: Organized commands for different functionalities
- **Interactive Prompts**: User-friendly interactive prompts
- **Progress Indicators**: Visual feedback for long-running operations
- **Formatted Output**: Tables, JSON syntax highlighting, and panels

## 📦 Installation

```bash
cd cli
pip install -r requirements.txt
```

## 🔧 Configuration

### Set API URL
```bash
# Environment variable
export REAA_API_URL="http://127.0.0.1:5000"

# Or use command
reaa config --url http://127.0.0.1:5000
```

### Set API Key
```bash
# Environment variable
export REAA_API_KEY="your-api-key-here"

# Or use command
reaa config --key your-api-key-here
```

## 📚 Usage

### Basic Commands

```bash
# Show version
reaa version

# Check system status
reaa status

# Show current configuration
reaa config
```

### Authentication

```bash
# Register new user
reaa auth register --username myuser --email my@email.com --password mypass

# Login
reaa auth login --username myuser --password mypass

# Get current user info
reaa auth me

# Logout
reaa auth logout
```

### Binary Analysis

```bash
# Upload binary
reaa analysis upload /path/to/binary.exe

# List all jobs
reaa analysis jobs

# Get job status
reaa analysis status <job-id>

# Delete job
reaa analysis delete <job-id>

# Download job artifacts
reaa analysis download <job-id> --output ./results
```

### Security Analysis

```bash
# Analyze for vulnerabilities
reaa security analyze <job-id> --message "Analyze for buffer overflows"

# Get security report
reaa security report <job-id>

# Scan binary
reaa security scan <job-id> --type comprehensive
```

### Active Reverse Engineering

```bash
# Plan execution strategy
reaa active-re plan /path/to/binary.exe --goal "vulnerability detection"

# Execute with Frida
reaa active-re execute <job-id> /path/to/binary.exe

# Monitor execution
reaa active-re monitor <job-id> --duration 30

# Chat with Active RE agent
reaa active-re chat "What API calls are being made?"
```

### RAG (Retrieval-Augmented Generation)

```bash
# Search knowledge base
reaa rag search "buffer overflow" --n 5

# Find similar functions
reaa rag similar-functions "int main() { return 0; }" --n 5

# Search vulnerability patterns
reaa rag vulnerabilities "strcpy(buffer, input)" --n 5
```

### Orchestrator

```bash
# Plan analysis strategy
reaa orchestrator plan /path/to/binary.exe --request "Comprehensive analysis"

# Execute orchestrated analysis
reaa orchestrator execute <job-id> /path/to/binary.exe

# List all tasks
reaa orchestrator tasks

# Approve operation
reaa orchestrator approve <job-id> --approve
```

### Radare2 Integration

```bash
# Get Radare2 status
reaa r2 status

# Analyze binary
reaa r2 analyze /path/to/binary.exe

# List functions
reaa r2 functions
```

### System Monitoring

```bash
# Check Docker status
reaa system docker

# Check GPU status
reaa system gpu

# View container logs
reaa system logs ghidra-api --lines 100
```

## 🎨 Output Examples

### Beautiful Tables
```
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Jobs List                                                     ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ id              │ filename    │ status     │ created_at         │
├────────────────────────────────────────────────────────────────┤
│ abc123...       │ test.exe    │ completed  │ 2024-01-15 10:30  │
│ def456...       │ malware.dll │ processing │ 2024-01-15 11:00  │
└────────────────────────────────────────────────────────────────┘
```

### JSON Syntax Highlighting
```json
{
  "job_id": "abc123...",
  "status": "completed",
  "filename": "test.exe"
}
```

### Progress Indicators
```
⠋ Uploading binary...
✓ Binary uploaded successfully
```

## 🔍 Help

```bash
# Show main help
reaa --help

# Show command group help
reaa analysis --help
reaa security --help
reaa active-re --help

# Show specific command help
reaa analysis upload --help
```

## 🌟 Features by Category

### Authentication (4 commands)
- `register` - Register new user
- `login` - Login and get API token
- `logout` - Logout current user
- `me` - Get current user info

### Analysis (5 commands)
- `upload` - Upload binary for analysis
- `jobs` - List all analysis jobs
- `status` - Get job status
- `delete` - Delete a job
- `download` - Download job artifacts

### Security (3 commands)
- `analyze` - Analyze for vulnerabilities
- `report` - Get security report
- `scan` - Scan binary for vulnerabilities

### Active RE (4 commands)
- `plan` - Plan execution strategy
- `execute` - Execute with Frida
- `monitor` - Monitor execution
- `chat` - Chat with Active RE agent

### RAG (3 commands)
- `search` - Search knowledge base
- `similar-functions` - Find similar functions
- `vulnerabilities` - Search vulnerability patterns

### Orchestrator (4 commands)
- `plan` - Plan analysis strategy
- `execute` - Execute orchestrated analysis
- `tasks` - List all tasks
- `approve` - Approve or reject operation

### Radare2 (3 commands)
- `status` - Get Radare2 status
- `analyze` - Analyze binary
- `functions` - List functions

### System (3 commands)
- `docker` - Check Docker status
- `gpu` - Check GPU status
- `logs` - View container logs

## 📝 Environment Variables

- `REAA_API_URL` - API base URL (default: http://127.0.0.1:5000)
- `REAA_API_KEY` - API authentication key

## 🐛 Troubleshooting

### Connection Error
```bash
# Check if API is running
reaa status

# Verify API URL
reaa config --url http://127.0.0.1:5000
```

### Authentication Error
```bash
# Login again
reaa auth login --username myuser --password mypass

# Check current user
reaa auth me
```

### File Not Found
```bash
# Verify file path exists
reaa analysis upload /absolute/path/to/binary.exe
```

## 🎯 Tips

1. **Use tab completion** - CLI supports auto-completion
2. **Use short flags** - `-u` instead of `--username`
3. **Pipe output** - Can pipe JSON output to other tools
4. **Save API key** - Set REAA_API_KEY environment variable for convenience
5. **Check status first** - Always run `reaa status` before starting analysis

## 📄 License

Same as REAA project license.
