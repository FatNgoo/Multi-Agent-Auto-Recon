# tasks/__init__.py
from .passive_recon_task import create_passive_recon_task
from .active_recon_task import create_active_recon_task, create_active_recon_task_simple
from .report_task import create_report_task, create_report_task_simple

__all__ = [
    "create_passive_recon_task",
    "create_active_recon_task",
    "create_active_recon_task_simple",
    "create_report_task",
    "create_report_task_simple",
]

