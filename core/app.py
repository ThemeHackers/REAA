import os
import json
import re
import uuid
from pathlib import Path
from base64 import b64decode
from typing import Optional, List, Dict, Any
import logging
import structlog
import psutil
from fastapi import FastAPI, UploadFile, File, HTTPException, Body
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel

from core.config import settings
from core.celery_app import celery_app
from core.tasks import run_ghidra_analysis


structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.JSONRenderer()
 ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
)

log = structlog.get_logger()


settings.DATA_DIR.mkdir(parents=True, exist_ok=True)

app = FastAPI(
    title=settings.API_TITLE,
    version=settings.API_VERSION,
    description="Production-ready Ghidra Headless REST API for AI-Assisted Reverse Engineering"
)

class AnalyzeResp(BaseModel):
    job_id: str
    status: str


@app.get("/mcp/descriptor")
def mcp_descriptor():
    """Get MCP tool descriptor"""
    if not settings.MCP_DESCRIPTOR.exists():
        raise HTTPException(status_code=500, detail="descriptor missing")
    return JSONResponse(content=json.loads(settings.MCP_DESCRIPTOR.read_text()))


@app.get("/mcp/tools")
def mcp_tools():
    """Get MCP tools definition"""
    if not settings.MCP_TOOLS.exists():
        raise HTTPException(status_code=500, detail="tools missing")
    return JSONResponse(content=json.loads(settings.MCP_TOOLS.read_text()))


@app.get("/health")
def health_check():
    """Health check endpoint"""
    health_status = {
        "status": "healthy",
        "service": settings.API_TITLE,
        "version": settings.API_VERSION
    }

    health_status["data_dir_accessible"] = settings.DATA_DIR.exists()
    
 
    health_status["ghidra_binary_exists"] = Path(settings.GHIDRA_BIN).exists()
   
    try:
        import redis
        r = redis.from_url(settings.REDIS_URL)
        r.ping()
        health_status["redis_connected"] = True
    except:
        health_status["redis_connected"] = False
    
   
    try:
        inspect = celery_app.control.inspect()
        workers = inspect.active()
        health_status["celery_workers"] = len(workers) if workers else 0
    except:
        health_status["celery_workers"] = 0
    
 
    health_status["system"] = {
        "cpu_percent": psutil.cpu_percent(),
        "memory_percent": psutil.virtual_memory().percent,
        "disk_percent": psutil.disk_usage('/').percent
    }
    

    if not all([
        health_status["data_dir_accessible"],
        health_status["ghidra_binary_exists"],
        health_status["redis_connected"]
    ]):
        health_status["status"] = "degraded"
        return JSONResponse(content=health_status, status_code=503)
    
    return JSONResponse(content=health_status)


@app.get("/metrics")
def metrics():
    """Prometheus-style metrics endpoint"""
    import time
    
    
    job_counts = {"queued": 0, "running": 0, "done": 0, "failed": 0}
    if settings.DATA_DIR.exists():
        for job_dir in settings.DATA_DIR.iterdir():
            if job_dir.is_dir():
                status_file = job_dir / "status.json"
                if status_file.exists():
                    try:
                        info = json.loads(status_file.read_text())
                        status = info.get("status", "unknown")
                        if status in job_counts:
                            job_counts[status] += 1
                    except:
                        pass
    
    metrics_data = {
        "timestamp": int(time.time()),
        "jobs": job_counts,
        "system": {
            "cpu_percent": psutil.cpu_percent(),
            "memory_percent": psutil.virtual_memory().percent,
            "disk_percent": psutil.disk_usage('/').percent,
            "disk_free_gb": psutil.disk_usage('/').free / (1024**3)
        }
    }
    
    return JSONResponse(content=metrics_data)


@app.get("/jobs")
def list_jobs():
    """List all analysis jobs"""
    jobs = []
    if settings.DATA_DIR.exists():
        for job_dir in settings.DATA_DIR.iterdir():
            if job_dir.is_dir():
                status_file = job_dir / "status.json"
                if status_file.exists():
                    try:
                        info = json.loads(status_file.read_text())
                        stat = status_file.stat()
                        info["created_at"] = stat.st_mtime
                        jobs.append(info)
                    except:
                        pass
    jobs.sort(key=lambda x: x.get("created_at", 0), reverse=True)
    return JSONResponse(content=jobs)


@app.post("/analyze", response_model=AnalyzeResp)
async def analyze(file: UploadFile = File(None), persist: bool = False):
    """Upload and analyze a binary file"""
    if file is None:
        raise HTTPException(status_code=400, detail="file is required")
    contents = await file.read()
    if len(contents) > settings.MAX_UPLOAD_SIZE:
        raise HTTPException(status_code=413, detail="file too large")
    return _launch_analysis(contents, file.filename, persist)


class AnalyzeB64Req(BaseModel):
    file_b64: str
    filename: str
    persist: Optional[bool] = False


@app.post("/analyze_b64", response_model=AnalyzeResp)
async def analyze_b64(payload: AnalyzeB64Req):
    """Upload and analyze a base64-encoded binary"""
    try:
        contents = b64decode(payload.file_b64)
    except Exception:
        raise HTTPException(status_code=400, detail="invalid base64")
    if len(contents) > settings.MAX_UPLOAD_SIZE:
        raise HTTPException(status_code=413, detail="file too large")
    return _launch_analysis(contents, payload.filename, bool(payload.persist))


def _launch_analysis(contents: bytes, filename: str, persist: bool) -> Dict[str, Any]:
    """
    Launch Ghidra analysis using Celery task queue
    """
    job_id = uuid.uuid4().hex
    proj_dir = settings.DATA_DIR / job_id
    proj_dir.mkdir(parents=True, exist_ok=True)

    binary_path = proj_dir / filename
    binary_path.write_bytes(contents)

    out_dir = proj_dir / "artifacts"
    out_dir.mkdir(exist_ok=True)


    status_file = proj_dir / "status.json"
    status_file.write_text(json.dumps({
        "job_id": job_id,
        "status": "queued",
        "filename": filename
    }))


    task = run_ghidra_analysis.delay(
        job_id=job_id,
        binary_path=str(binary_path),
        filename=filename,
        persist=persist
    )

    log.info(f"Launched Ghidra analysis task {task.id} for job {job_id}")
    
    return {"job_id": job_id, "status": "queued", "task_id": task.id}


@app.get("/status/{job_id}")
def status(job_id: str):
    """Get status of an analysis job"""
    status_file = settings.DATA_DIR / job_id / "status.json"
    if not status_file.exists():
        raise HTTPException(status_code=404, detail="job not found")
    return JSONResponse(content=json.loads(status_file.read_text()))


@app.get("/status/{job_id}/celery")
def status_celery(job_id: str):
    """Get detailed Celery task status for an analysis job"""
    status_file = settings.DATA_DIR / job_id / "status.json"
    if not status_file.exists():
        raise HTTPException(status_code=404, detail="job not found")
    
    status_data = json.loads(status_file.read_text())
    task_id = status_data.get("task_id")
    
    if task_id:
        task_result = celery_app.AsyncResult(task_id)
        return JSONResponse(content={
        "job_id": job_id,
        "task_id": task_id,
        "task_status": task_result.status,
        "task_info": task_result.info if task_result.info else None,
        "file_status": status_data
        })
    else:
        return JSONResponse(content=status_data)


@app.get("/results/{job_id}/functions")
def list_functions(job_id: str, offset: int = 0, limit: int = 100):
    """List functions with pagination"""
    f = settings.DATA_DIR / job_id / "artifacts" / "functions.json"
    if not f.exists():
        raise HTTPException(status_code=404, detail="functions not found or analysis still running")
    
    data = json.loads(f.read_text())
    all_funcs = data.get("functions", [])
    total = len(all_funcs)
    
    sliced = all_funcs[offset : offset + limit]
    
    return JSONResponse(content={
        "total": total,
        "offset": offset,
        "limit": limit,
        "functions": sliced
    })


@app.get("/results/{job_id}/function/{addr}/decompile")
def get_decompile(job_id: str, addr: str):
    """Get decompiled pseudocode for a function"""
    addr_norm = addr.lower()
    if not addr_norm.startswith("0x"):
        addr_norm = "0x" + addr_norm
    f = settings.DATA_DIR / job_id / "artifacts" / f"decompile_{addr_norm}.c"
    if not f.exists():
        f2 = settings.DATA_DIR / job_id / "artifacts" / f"decompile_{addr}.c"
        if f2.exists():
            f = f2
        else:
            raise HTTPException(status_code=404, detail="decompile not found")
    return PlainTextResponse(content=f.read_text(), media_type="text/plain")


@app.get("/results/{job_id}/xrefs/{addr}")
def get_xrefs(job_id: str, addr: str):
    """Get cross-references for an address"""
    f = settings.DATA_DIR / job_id / "artifacts" / "xrefs.json"
    if not f.exists():
        raise HTTPException(status_code=404, detail="xrefs not available")
    data = json.loads(f.read_text())
    return JSONResponse(content={"addr": addr, "xrefs": data.get(addr, {})})


@app.get("/results/{job_id}/imports")
def list_imports(job_id: str):
    """List imported libraries and symbols"""
    f = settings.DATA_DIR / job_id / "artifacts" / "imports.json"
    if not f.exists():
        raise HTTPException(status_code=404, detail="imports not available")
    return JSONResponse(content=json.loads(f.read_text()))


@app.get("/results/{job_id}/strings")
def list_strings(job_id: str, min_length: int = 4):
    """List printable strings from the binary"""
    f = settings.DATA_DIR / job_id / "artifacts" / "strings.json"
    if not f.exists():
        raise HTTPException(status_code=404, detail="strings not available")
    all_strings = json.loads(f.read_text())
    filtered = [s for s in all_strings if len(s.get("s", "")) >= min_length]
    return JSONResponse(content={"count": len(filtered), "strings": filtered})


@app.post("/query")
def query(payload: Dict[str, Any] = Body(...)):
    """Query artifacts with natural language or regex"""
    job_id = payload.get("job_id")
    q = payload.get("query", "")
    use_regex = payload.get("regex", False)
    
    if not job_id:
        raise HTTPException(status_code=400, detail="job_id required")
        
    proj = settings.DATA_DIR / job_id
    if not proj.exists():
        raise HTTPException(status_code=404, detail="job not found")
    
    matches = []
    
    def matches_query(text: str) -> bool:
        if not text: return False
        if not q: return True
        if use_regex:
            try:
                return re.search(q, text, re.IGNORECASE) is not None
            except re.error:
                return False
        return q.lower() in text.lower()


    fjson = proj / "artifacts" / "functions.json"
    if fjson.exists():
        data = json.loads(fjson.read_text())
        funcs = data.get("functions", [])
        
        for fn in funcs:
            reasons = []
            if q:
                if matches_query(fn.get("name", "")):
                    reasons.append("name_match")
                elif matches_query(fn.get("decompiled_excerpt", "")):
                    reasons.append("code_match")
            
            if reasons or (not q):
                if reasons:
                     matches.append({"type": "function", "name": fn.get("name"), "addr": fn.get("addr"), "reasons": reasons})

    sjson = proj / "artifacts" / "strings.json"
    if sjson.exists() and q:
        strs = json.loads(sjson.read_text())
        for s in strs:
            if matches_query(s.get("s", "")):
                 matches.append({"type": "string", "val": s.get("s"), "addr": s.get("addr"), "is_defined": s.get("is_defined", False)})
    
    return {"query": q, "count": len(matches), "matches": matches[:50]}



class ToolAnalyzeReq(BaseModel):
    file_b64: str
    filename: str
    persist: Optional[bool] = False


@app.post("/tools/analyze")
async def tools_analyze(payload: ToolAnalyzeReq):
    return await analyze_b64(payload)


class ToolStatusReq(BaseModel):
    job_id: str


@app.post("/tools/status")
def tools_status(payload: ToolStatusReq):
    return status(payload.job_id)


class ToolListFunctionsReq(BaseModel):
    job_id: str
    offset: Optional[int] = 0
    limit: Optional[int] = 100


@app.post("/tools/list_functions")
def tools_list_functions(payload: ToolListFunctionsReq):
    return list_functions(payload.job_id, payload.offset, payload.limit)


class ToolDecompileReq(BaseModel):
    job_id: str
    addr: str


@app.post("/tools/decompile_function")
def tools_decompile(payload: ToolDecompileReq):
    return get_decompile(payload.job_id, payload.addr)


class ToolXrefsReq(BaseModel):
    job_id: str
    addr: str


@app.post("/tools/get_xrefs")
def tools_get_xrefs(payload: ToolXrefsReq):
    return get_xrefs(payload.job_id, payload.addr)


class ToolImportsReq(BaseModel):
    job_id: str


@app.post("/tools/list_imports")
def tools_list_imports(payload: ToolImportsReq):
    return list_imports(payload.job_id)


class ToolStringsReq(BaseModel):
    job_id: str
    min_length: Optional[int] = 4


@app.post("/tools/list_strings")
def tools_list_strings(payload: ToolStringsReq):
    return list_strings(payload.job_id, payload.min_length)


class ToolQueryReq(BaseModel):
    job_id: str
    query: str
    regex: Optional[bool] = False


@app.post("/tools/query_artifacts")
def tools_query(payload: ToolQueryReq):
    return query(payload.dict())