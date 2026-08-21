from celery import Celery
from app.core.config import settings

# Configure Celery with Redis broker and result backend
celery_app = Celery(
    "pentest_tasks",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_always_eager=(settings.ENVIRONMENT == "development"),
    broker_connection_retry_on_startup=True
)
