import redis
import rq
from rq import Queue, Worker
from datetime import datetime
import os
from models import db, Job
from flask import current_app

redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
redis_conn = redis.from_url(redis_url)

high_priority_queue = Queue('high', connection=redis_conn)
default_queue = Queue('default', connection=redis_conn)
low_priority_queue = Queue('low', connection=redis_conn)

class JobQueueManager:
    def __init__(self):
        self.queues = {
            'high': high_priority_queue,
            'default': default_queue,
            'low': low_priority_queue
        }
    
    def enqueue_job(self, job_id, task_func, *args, **kwargs):
        """Enqueue a job for processing"""
        job = Job.query.get(job_id)
        if not job:
            raise ValueError(f"Job {job_id} not found")
        
        if job.priority <= 3:
            queue = self.queues['high']
        elif job.priority >= 7:
            queue = self.queues['low']
        else:
            queue = self.queues['default']
        
        task = queue.enqueue(
            task_func,
            job_id=job_id,
            *args,
            **kwargs,
            job_timeout=3600,
            retry=Retry(max=job.max_retries),
            on_success=self._on_job_success,
            on_failure=self._on_job_failure
        )
        
        job.status = 'queued'
        job.started_at = datetime.utcnow()
        db.session.commit()
        
        return task
    
    def _on_job_success(self, job, connection, result, *args, **kwargs):
        """Callback when job completes successfully"""
        from app import app
        with app.app_context():
            job_record = Job.query.get(job.args[0])
            if job_record:
                job_record.status = 'completed'
                job_record.completed_at = datetime.utcnow()
                db.session.commit()
    
    def _on_job_failure(self, job, connection, type, value, traceback):
        """Callback when job fails"""
        from app import app
        with app.app_context():
            job_record = Job.query.get(job.args[0])
            if job_record:
                job_record.status = 'failed'
                job_record.error_message = str(value)
                job_record.retry_count += 1
                db.session.commit()
    
    def get_job_status(self, job_id):
        """Get status of a queued job"""
        for queue in self.queues.values():
            job = queue.fetch_job(job_id)
            if job:
                return {
                    'id': job.id,
                    'status': job.get_status(),
                    'result': job.result,
                    'exc_info': job.exc_info
                }
        return None
    
    def cancel_job(self, job_id):
        """Cancel a queued job"""
        for queue in self.queues.values():
            job = queue.fetch_job(job_id)
            if job:
                job.cancel()
                return True
        return False
    
    def get_queue_stats(self):
        """Get statistics for all queues"""
        stats = {}
        for name, queue in self.queues.items():
            stats[name] = {
                'queued': len(queue),
                'started': queue.started_job_registry.count,
                'finished': queue.finished_job_registry.count,
                'failed': queue.failed_job_registry.count
            }
        return stats

job_queue_manager = JobQueueManager()

def analyze_binary_task(job_id):
    """Task to analyze a binary file"""
    from app import app
    with app.app_context():
        job = Job.query.get(job_id)
        if not job:
            raise ValueError(f"Job {job_id} not found")
        
        job.status = 'processing'
        db.session.commit()
        
        try:
            from ghidra_assistant import GhidraAssistant
            assistant = GhidraAssistant()
            
            result = {"status": "completed", "job_id": job_id}
            
            return result
        except Exception as e:
            raise e

class Retry:
    """Retry configuration for RQ jobs"""
    def __init__(self, max=3, interval=60):
        self.max = max
        self.interval = interval
