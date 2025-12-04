"""Scheduler - Lightweight cron-like job scheduler"""
import asyncio
import logging
from datetime import datetime, timezone
from typing import Dict, List, Callable, Any, Optional
import uuid
from dataclasses import dataclass
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.triggers.date import DateTrigger

logger = logging.getLogger(__name__)


@dataclass
class ScheduledJob:
    """Scheduled job configuration"""
    id: str
    name: str
    func: Callable
    trigger_type: str  # cron, interval, date
    trigger_args: Dict[str, Any]
    enabled: bool = True
    last_run: Optional[datetime] = None
    next_run: Optional[datetime] = None
    run_count: int = 0
    
    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'name': self.name,
            'trigger_type': self.trigger_type,
            'trigger_args': self.trigger_args,
            'enabled': self.enabled,
            'last_run': self.last_run.isoformat() if self.last_run else None,
            'next_run': self.next_run.isoformat() if self.next_run else None,
            'run_count': self.run_count
        }


class Scheduler:
    """APScheduler-based job scheduler"""
    
    _instance: Optional['Scheduler'] = None
    
    def __init__(self):
        self._scheduler = AsyncIOScheduler()
        self._jobs: Dict[str, ScheduledJob] = {}
        self._running = False
        
    @classmethod
    def get_instance(cls) -> 'Scheduler':
        """Get singleton instance"""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance
    
    def start(self):
        """Start the scheduler"""
        if not self._running:
            self._scheduler.start()
            self._running = True
            logger.info("Scheduler started")
    
    def stop(self):
        """Stop the scheduler"""
        if self._running:
            self._scheduler.shutdown()
            self._running = False
            logger.info("Scheduler stopped")
    
    def add_job(
        self,
        func: Callable,
        name: str,
        trigger_type: str = "interval",
        **trigger_args
    ) -> str:
        """Add a scheduled job"""
        job_id = str(uuid.uuid4())
        
        # Create trigger based on type
        if trigger_type == "cron":
            trigger = CronTrigger(**trigger_args)
        elif trigger_type == "interval":
            trigger = IntervalTrigger(**trigger_args)
        elif trigger_type == "date":
            trigger = DateTrigger(**trigger_args)
        else:
            raise ValueError(f"Unknown trigger type: {trigger_type}")
        
        # Wrapper to track execution
        async def job_wrapper():
            job = self._jobs.get(job_id)
            if job and job.enabled:
                try:
                    job.last_run = datetime.now(timezone.utc)
                    job.run_count += 1
                    if asyncio.iscoroutinefunction(func):
                        await func()
                    else:
                        func()
                    logger.info(f"Job {name} executed successfully")
                except Exception as e:
                    logger.error(f"Job {name} failed: {e}")
        
        # Add to APScheduler
        self._scheduler.add_job(
            job_wrapper,
            trigger=trigger,
            id=job_id,
            name=name
        )
        
        # Track job
        self._jobs[job_id] = ScheduledJob(
            id=job_id,
            name=name,
            func=func,
            trigger_type=trigger_type,
            trigger_args=trigger_args
        )
        
        logger.info(f"Added scheduled job: {name} ({trigger_type})")
        return job_id
    
    def add_cron_job(self, func: Callable, name: str, cron_expression: str) -> str:
        """Add a job with cron expression (e.g., '0 */6 * * *')"""
        parts = cron_expression.split()
        if len(parts) != 5:
            raise ValueError("Cron expression must have 5 parts: minute hour day month day_of_week")
        
        return self.add_job(
            func, name, "cron",
            minute=parts[0],
            hour=parts[1],
            day=parts[2],
            month=parts[3],
            day_of_week=parts[4]
        )
    
    def add_interval_job(self, func: Callable, name: str, seconds: int = None, minutes: int = None, hours: int = None) -> str:
        """Add an interval-based job"""
        trigger_args = {}
        if seconds:
            trigger_args['seconds'] = seconds
        if minutes:
            trigger_args['minutes'] = minutes
        if hours:
            trigger_args['hours'] = hours
        
        return self.add_job(func, name, "interval", **trigger_args)
    
    def remove_job(self, job_id: str) -> bool:
        """Remove a scheduled job"""
        if job_id in self._jobs:
            try:
                self._scheduler.remove_job(job_id)
            except Exception:
                pass
            del self._jobs[job_id]
            logger.info(f"Removed job: {job_id}")
            return True
        return False
    
    def pause_job(self, job_id: str) -> bool:
        """Pause a job"""
        if job_id in self._jobs:
            self._jobs[job_id].enabled = False
            try:
                self._scheduler.pause_job(job_id)
            except Exception:
                pass
            return True
        return False
    
    def resume_job(self, job_id: str) -> bool:
        """Resume a paused job"""
        if job_id in self._jobs:
            self._jobs[job_id].enabled = True
            try:
                self._scheduler.resume_job(job_id)
            except Exception:
                pass
            return True
        return False
    
    def trigger_job(self, job_id: str) -> bool:
        """Trigger a job immediately"""
        if job_id in self._jobs:
            try:
                # Run the job function directly
                job = self._jobs[job_id]
                asyncio.create_task(self._run_job_now(job))
                return True
            except Exception as e:
                logger.error(f"Failed to trigger job {job_id}: {e}")
        return False
    
    async def _run_job_now(self, job: ScheduledJob):
        """Run a job immediately"""
        try:
            job.last_run = datetime.now(timezone.utc)
            job.run_count += 1
            if asyncio.iscoroutinefunction(job.func):
                await job.func()
            else:
                job.func()
        except Exception as e:
            logger.error(f"Job {job.name} failed: {e}")
    
    def get_job(self, job_id: str) -> Optional[ScheduledJob]:
        """Get job by ID"""
        return self._jobs.get(job_id)
    
    def list_jobs(self) -> List[Dict]:
        """List all scheduled jobs"""
        result = []
        for job_id, job in self._jobs.items():
            # Get next run time from APScheduler
            try:
                apscheduler_job = self._scheduler.get_job(job_id)
                if apscheduler_job:
                    job.next_run = apscheduler_job.next_run_time
            except Exception:
                pass
            result.append(job.to_dict())
        return result
    
    @property
    def is_running(self) -> bool:
        return self._running


# Global scheduler instance
scheduler = Scheduler.get_instance()
