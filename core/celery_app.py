"""
Celery application for async task processing
"""
from celery import Celery
from core.config import settings


celery_app = Celery(
    "ghidra_tasks",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=["core.tasks"]
)


celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=settings.CELERY_TASK_TIMEOUT,
    task_soft_time_limit=settings.CELERY_TASK_TIMEOUT - 60,
    worker_prefetch_multiplier=1,
    worker_max_tasks_per_child=1,
    result_expires=3600,  
)


celery_app.conf.beat_schedule = {

}
