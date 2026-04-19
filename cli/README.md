# REAA CLI - Command Line Interface


## ⚠️ Prerequisites

**IMPORTANT:** You must activate the virtual environment before using the CLI:

```bash
# Windows (PowerShell)
.venv\Scripts\activate

# Linux/Mac
source .venv/bin/activate
```

After activation, use the `reaa` command directly:

```bash
reaa --help
```

Or use the full path if you prefer:

```bash
.venv\Scripts\reaa.exe --help
```

### Authentication Required

**Most commands require authentication.** You must login first:

```bash
# Register if you don't have an account
reaa auth register --username <username> --email <email> --password <password>

# Login with your credentials
reaa auth login --username <username> --password <password>

# Check if you're logged in
reaa auth me

# Logout when done
reaa auth logout
```

## 📦 Installation

```bash
# Activate virtual environment first
.venv\Scripts\activate

# Navigate to CLI directory
cd cli

# Install dependencies
pip install -r requirements.txt

# Install CLI in editable mode
pip install -e .
```

## 🔧 Configuration

### Set API URL
```bash
# Linux/Mac (bash)
export REAA_API_URL="http://127.0.0.1:5000"

# Windows (PowerShell)
$env:REAA_API_URL="http://127.0.0.1:5000"

# Or use command
reaa config --url http://127.0.0.1:5000
```

### Set API Key
```bash
# Linux/Mac (bash)
export REAA_API_KEY="your-api-key-here"

# Windows (PowerShell)
$env:REAA_API_KEY="your-api-key-here"

# Or use command
reaa config --key your-api-key-here
```

## 📚 Usage

**Before using any commands, make sure you've activated the virtual environment:**

```bash
.venv\Scripts\activate
```

### Basic Commands

```bash
# Show help
reaa --help

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

# Memory layout
reaa analysis memory <job-id>

# Memory hex dump
reaa analysis memory-hex <job-id> <section_name>

# Memory analysis
reaa analysis memory-analysis <job-id>

# Memory strings
reaa analysis memory-strings <job-id>

# Memory cross-references
reaa analysis memory-xref <job-id> <address>

# Memory compare
reaa analysis memory-compare <job-id> <section1> <section2>

# Memory search
reaa analysis memory-search <job-id> <pattern>
```

### Security Analysis

```bash
# Analyze for vulnerabilities
reaa security analyze <job-id> --message "Analyze for buffer overflows"

# Get security report
reaa security report <job-id>

# Security audit
reaa security audit <job-id>

# Security metrics
reaa security metrics <job-id>

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

# Approve or reject operation
reaa orchestrator approve <job-id> --approve
reaa orchestrator approve <job-id> --reject
```

### Radare2 Integration

```bash
# Get Radare2 status
reaa r2 status

# List functions
reaa r2 functions
```

### Remote Collaboration

```bash
# Check remote collaboration health
reaa remote health

# Get remote server status
reaa remote server-status

# List remote jobs
reaa remote jobs

# Get users in remote room
reaa remote room-users <job-id>

# List remote API keys
reaa remote api-keys

# Create new API key
reaa remote create-key

# Delete API key
reaa remote delete-key <api-key>
```

### Settings & Models

```bash
# View or update settings
reaa settings --key <key> --value <value>

# Manage AI models
reaa models --action list      # List available models
reaa models --action current   # Show current model
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

### Analysis (12 commands)
- `upload` - Upload binary for analysis
- `jobs` - List all analysis jobs
- `status` - Get job status
- `delete` - Delete a job
- `download` - Download job artifacts
- `memory` - Get memory layout
- `memory-hex` - Get memory hex dump
- `memory-analysis` - Analyze memory
- `memory-strings` - Extract memory strings
- `memory-xref` - Get memory cross-references
- `memory-compare` - Compare memory regions
- `memory-search` - Search memory

### Security (5 commands)
- `analyze` - Analyze for vulnerabilities
- `report` - Get security report
- `audit` - Security audit
- `metrics` - Security metrics
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

### Radare2 (2 commands)
- `status` - Get Radare2 status
- `functions` - List functions

### System (3 commands)
- `docker` - Check Docker status
- `gpu` - Check GPU status
- `logs` - View container logs

### Remote Collaboration (7 commands)
- `health` - Check remote collaboration health
- `server-status` - Get remote server status
- `jobs` - List remote jobs
- `room-users` - Get users in remote room
- `api-keys` - List remote API keys
- `create-key` - Create new API key
- `delete-key` - Delete API key

### Main Commands (6 commands)
- `version` - Show CLI version
- `run` - Start webui server in background
- `status` - Check system status
- `config` - Configure CLI settings
- `settings` - Update or view settings
- `models` - Manage AI models

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
