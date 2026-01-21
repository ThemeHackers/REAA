# AI-Assisted Reverse Engineering with Ghidra

This tool gives security researchers an AI chat interface that can drive Ghidra through MCP, letting them ask high-level questions about a binary instead of digging manually. The agentic workflow automatically performs the required reverse-engineering steps inside Ghidra to produce answers.

#### Uses a headless Ghidra analysis results exposed as REST API

```bash
docker run --rm -p 9090:9090 -v $(pwd)/data:/data/ghidra_projects biniamfd/ghidra-headless-rest:latest
```
## Headless Ghidra endpoints (at GHIDRA_API_BASE = http://localhost:9090)
| Endpoint                    | Method | Description                                                        | Parameters                                                                                                                 | Returns                                                                                     |
| --------------------------- | ------ | ------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| `/tools/analyze`            | POST   | Upload a base64-encoded binary and start headless Ghidra analysis. | **file_b64** *(string, required)* – Base64-encoded binary<br>**filename** *(string, required)* – Original filename         | **job_id** *(string)* – Analysis job identifier                                             |
| `/tools/status`             | POST   | Get status for an existing analysis job.                           | **job_id** *(string, required)* – Analysis job identifier                                                                  | **job_id** *(string)*<br>**status** *(string)* – `queued \| running \| completed \| failed` |
| `/tools/list_functions`     | POST   | Retrieve the list of discovered functions for a job.               | **job_id** *(string, required)* – Analysis job identifier                                                                  | **functions** *(array)* – List of `{ name: string, address: string }`                       |
| `/tools/decompile_function` | POST   | Get decompiled pseudocode for a function at a given address.       | **job_id** *(string, required)* – Analysis job identifier<br>**addr** *(string, required)* – Function address (hex string) | **address** *(string)*<br>**pseudocode** *(string)* – Decompiled C-like code                |
| `/tools/get_xrefs`          | POST   | Get callers and callees for a function (cross-references).         | **job_id** *(string, required)* – Analysis job identifier<br>**addr** *(string, required)* – Function address              | **address** *(string)*<br>**callers** *(string[])*<br>**callees** *(string[])*              |
| `/tools/list_imports`       | POST   | List imported libraries and symbols for the binary.                | **job_id** *(string, required)* – Analysis job identifier                                                                  | **imports** *(array)* – List of `{ library: string, symbol: string }`                       |
| `/tools/list_strings`       | POST   | Return printable strings extracted from the binary.                | **job_id** *(string, required)* – Analysis job identifier<br>**min_length** *(integer, optional)* – Minimum string length  | **strings** *(string[])*                                                                    |
| `/tools/query_artifacts`    | POST   | Natural-language-style query over artifacts.                       | **job_id** *(string, required)* – Analysis job identifier<br>**query** *(string, required)* – Query text                   | **results** *(array)* – Matching functions / snippets                                       |

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

