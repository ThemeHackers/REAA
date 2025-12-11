# AI-Assisted Reverse Engineering with Ghidra

This tool gives security researchers an AI chat interface that can drive Ghidra through MCP, letting them ask high-level questions about a binary instead of digging manually. The agentic workflow automatically performs the required reverse-engineering steps inside Ghidra to produce answers.

#### Uses a headless Ghidra analysis results exposed as REST API

```bash
docker run --rm -p 9090:9090 -v $(pwd)/data:/data/ghidra_projects biniamfd/ghidra-headless-rest:latest
```
## Headless Ghidra endpoints (at GHIDRA_API_BASE = http://localhost:9090)
 endpoint | description 
 ---|---
/tools/analyze | Upload a base64-encoded binary and start headless Ghidra analysis. 
/tools/status | Get status for an existing analysis job.
/tools/list_functions | Retrieve the list of discovered functions for a job.
/tools/decompile_function | Get decompiled pseudocode for a function at a given address.
/tools/get_xrefs | Get callers and callees for a function (cross-references).
/tools/list_imports | List imported libraries and symbols for the binary.
/tools/list_strings | Return printable strings extracted from the binary.
/tools/query_artifacts | Simple natural-language-like query over artifacts (function names, decompiled snippets).

## Architecture
<img width="916" height="651" alt="image" src="https://github.com/user-attachments/assets/4e75fdca-fc5f-4da2-823e-05d209e2c6b2" />

## Setup

- Pull the Docker image and run it
- Set your OpenAI compatible API base URL
- API key
- model name

```bash
python webui/app.py
```

Then access the service at http://localhost:5000


https://github.com/user-attachments/assets/77f1645a-cd8e-470f-826b-585a73e48bf4

