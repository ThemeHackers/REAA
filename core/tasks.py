"""
Celery tasks for Ghidra analysis
"""
import os
import json
import logging
from pathlib import Path
from celery import current_task
from core.celery_app import celery_app
from core.config import settings
from core.llm_refiner import get_refiner

log = logging.getLogger(__name__)


@celery_app.task(bind=True, name="core.tasks.run_ghidra_analysis")
def run_ghidra_analysis(self, job_id: str, binary_path: str, filename: str, persist: bool = False, enable_refinement: bool = False):
    """
    Execute Ghidra headless analysis as a Celery task using PyGhidra new API
    
    Args:
        job_id: Unique job identifier
        binary_path: Path to the binary file
        filename: Original filename
        persist: Whether to keep the Ghidra project after analysis
        enable_refinement: Whether to enable LLM-based pseudo-code refinement
    """
    proj_dir = settings.DATA_DIR / job_id
    out_dir = proj_dir / "artifacts"
    out_dir.mkdir(exist_ok=True, parents=True)
    
    project_name = f"proj_{job_id}"
    script_path = "/app/ghidra_scripts/export_json.py"
    
    status_file = proj_dir / "status.json"
    
    status_file.write_text(json.dumps({
        "job_id": job_id,
        "status": "running",
        "filename": filename,
        "task_id": self.request.id
    }))
    
    try:
        self.update_state(state="PROGRESS", meta={"status": "running", "progress": 0})
        
        log.info(f"Starting Ghidra analysis for job {job_id}")
      
        import pyghidra
        log.info(f"PyGhidra imported successfully")
      
        os.environ['GHIDRA_EXPORT_DIR'] = str(out_dir)
        log.info(f"Export directory set to {out_dir}")
        
    
        
        if not pyghidra.started():
            log.info("Starting PyGhidra...")
            pyghidra.start(install_dir=settings.GHIDRA_HOME)
            log.info("PyGhidra started successfully")
        else:
            log.info("PyGhidra already started")

        log.info(f"Opening project at {proj_dir}")
        with pyghidra.open_project(str(proj_dir), project_name, create=True) as project:
            log.info(f"Project opened successfully")
            
            log.info(f"Loading binary from {binary_path}")
            loader = pyghidra.program_loader().project(project).source(str(binary_path))
            with loader.load() as load_results:
                load_results.save(pyghidra.task_monitor())
                log.info(f"Binary loaded and saved successfully")
            

            log.info(f"Consuming program from project")
            program, consumer = pyghidra.consume_program(project, "/" + os.path.basename(binary_path))
            log.info(f"Program consumed successfully")
            try:
                self.update_state(state="PROGRESS", meta={"status": "analyzing", "progress": 30})
                log.info(f"Starting analysis...")
                analysis_log = pyghidra.analyze(program, pyghidra.task_monitor(settings.CELERY_TASK_TIMEOUT))
                log.info(f"Analysis completed for job {job_id}")
                
                self.update_state(state="PROGRESS", meta={"status": "exporting", "progress": 70})
                log.info(f"Running export script...")
                stdout, stderr = pyghidra.ghidra_script(
                    script_path, 
                    project, 
                    program,
                    echo_stdout=True,
                    echo_stderr=True
                )
                
                log.info(f"Export completed for job {job_id}")
                if stdout:
                    log.info(f"Script stdout:\n{stdout}")
                if stderr:
                    log.warning(f"Script stderr:\n{stderr}")
            finally:
                log.info(f"Releasing program")
                program.release(consumer)
                log.info(f"Program released successfully")
        
        status_file.write_text(json.dumps({
            "job_id": job_id,
            "status": "done",
            "filename": filename,
            "enable_refinement": enable_refinement,
            "task_id": self.request.id
        }))
        

        if enable_refinement:
            self.update_state(state="PROGRESS", meta={"status": "refining", "progress": 80})
            log.info(f"Starting LLM refinement for job {job_id}")
            _run_refinement(job_id, out_dir)
            log.info(f"LLM refinement completed for job {job_id}")
        
        return {
            "job_id": job_id,
            "status": "done",
            "filename": filename,
            "refinement_enabled": enable_refinement
        }
        
    except Exception as e:
        log.error(f"Error during Ghidra analysis for job {job_id}: {e}", exc_info=True)
        status_file.write_text(json.dumps({
            "job_id": job_id,
            "status": "failed",
            "reason": str(e),
            "task_id": self.request.id
        }))
        self.update_state(
            state="FAILURE",
            meta={"job_id": job_id, "status": "failed", "reason": str(e)}
        )
        raise


@celery_app.task(name="core.tasks.cleanup_old_jobs")
def cleanup_old_jobs():
    """
    Periodic task to clean up old completed jobs
    """
    import time
    from datetime import datetime, timedelta
    
    cutoff_time = datetime.now() - timedelta(days=7)  
    
    if not settings.DATA_DIR.exists():
        return {"cleaned": 0, "message": "Data directory does not exist"}
    
    cleaned_count = 0
    for job_dir in settings.DATA_DIR.iterdir():
        if job_dir.is_dir():
            status_file = job_dir / "status.json"
            if status_file.exists():
                try:
                    stat = status_file.stat()
                    mod_time = datetime.fromtimestamp(stat.st_mtime)
                    

                    if mod_time < cutoff_time:
                        info = json.loads(status_file.read_text())
                        if info.get("status") in ["done", "failed"]:
                         
                            import shutil
                            shutil.rmtree(job_dir)
                            cleaned_count += 1
                            log.info(f"Cleaned up old job: {job_dir.name}")
                except Exception as e:
                    log.error(f"Error cleaning up job {job_dir.name}: {e}")
    
    return {"cleaned": cleaned_count, "message": f"Cleaned {cleaned_count} old jobs"}


def _run_refinement(job_id: str, artifacts_dir: Path):
    """
    Run LLM refinement on all decompiled functions
    
    Args:
        job_id: Job identifier
        artifacts_dir: Path to the artifacts directory
    """
    try:
        
        refiner = get_refiner()
        if not refiner.is_available():
            log.warning("LLM refiner not available, skipping refinement")
            return
        
    
        decompile_files = list(artifacts_dir.glob("decompile_*.c"))
        if not decompile_files:
            log.warning("No decompiled files found for refinement")
            return
        
      
        refine_dir = artifacts_dir / "refine"
        refine_dir.mkdir(exist_ok=True)
        
        log.info(f"Found {len(decompile_files)} decompiled files to refine")
        
        refined_count = 0
        for decompile_file in decompile_files:
            try:
              
                filename = decompile_file.name
              
                if filename.startswith("decompile_") and filename.endswith(".c"):
                    address = filename[len("decompile_"):-2]
                    output_file = refine_dir / f"{address}.c"
                else:
                    log.warning(f"Unexpected filename format: {filename}")
                    continue
                
              
                success = refiner.refine_function_from_file(decompile_file, output_file)
                if success:
                    refined_count += 1
                    log.info(f"Refined {filename} -> {output_file.name}")
                else:
                    log.warning(f"Failed to refine {filename}")
                    
            except Exception as e:
                log.error(f"Error refining {decompile_file}: {e}")
        
        log.info(f"Refinement completed: {refined_count}/{len(decompile_files)} files refined")
        
    except Exception as e:
        log.error(f"Error during refinement: {e}", exc_info=True)
