"""Workflow Manager - Chain and orchestrate multi-step scan workflows"""
import asyncio
import logging
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Any, Callable, Optional
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class StepStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class WorkflowStep:
    """A single step in a workflow"""
    id: str
    name: str
    action: Callable
    depends_on: List[str] = field(default_factory=list)
    condition: Optional[Callable] = None  # Condition to run this step
    retry_count: int = 0
    timeout: int = 300
    status: StepStatus = StepStatus.PENDING
    result: Any = None
    error: Optional[str] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None


@dataclass
class Workflow:
    """A workflow containing multiple steps"""
    id: str
    name: str
    steps: Dict[str, WorkflowStep] = field(default_factory=dict)
    context: Dict[str, Any] = field(default_factory=dict)
    status: StepStatus = StepStatus.PENDING
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def add_step(
        self,
        name: str,
        action: Callable,
        depends_on: List[str] = None,
        condition: Callable = None,
        timeout: int = 300
    ) -> str:
        """Add a step to the workflow"""
        step_id = str(uuid.uuid4())
        self.steps[step_id] = WorkflowStep(
            id=step_id,
            name=name,
            action=action,
            depends_on=depends_on or [],
            condition=condition,
            timeout=timeout
        )
        return step_id


class WorkflowManager:
    """Manages and executes workflows"""
    
    def __init__(self):
        self._workflows: Dict[str, Workflow] = {}
        self._templates: Dict[str, Callable[[], Workflow]] = {}
        
    def create_workflow(self, name: str) -> Workflow:
        """Create a new workflow"""
        workflow = Workflow(
            id=str(uuid.uuid4()),
            name=name
        )
        self._workflows[workflow.id] = workflow
        return workflow
    
    def register_template(self, name: str, builder: Callable[[], Workflow]):
        """Register a workflow template"""
        self._templates[name] = builder
    
    def create_from_template(self, template_name: str) -> Optional[Workflow]:
        """Create workflow from a registered template"""
        if template_name in self._templates:
            workflow = self._templates[template_name]()
            self._workflows[workflow.id] = workflow
            return workflow
        return None
    
    async def execute(self, workflow: Workflow) -> Dict[str, Any]:
        """Execute a workflow"""
        workflow.status = StepStatus.RUNNING
        logger.info(f"Starting workflow: {workflow.name}")
        
        try:
            # Build execution order based on dependencies
            execution_order = self._resolve_dependencies(workflow)
            
            for step_id in execution_order:
                step = workflow.steps[step_id]
                
                # Check if dependencies completed
                deps_ok = all(
                    workflow.steps[dep_id].status == StepStatus.COMPLETED
                    for dep_id in step.depends_on
                    if dep_id in workflow.steps
                )
                
                if not deps_ok:
                    step.status = StepStatus.SKIPPED
                    logger.warning(f"Skipping step {step.name}: dependencies not met")
                    continue
                
                # Check condition
                if step.condition:
                    try:
                        if not step.condition(workflow.context):
                            step.status = StepStatus.SKIPPED
                            logger.info(f"Skipping step {step.name}: condition not met")
                            continue
                    except Exception as e:
                        logger.error(f"Condition check failed for {step.name}: {e}")
                        continue
                
                # Execute step
                await self._execute_step(step, workflow.context)
                
                # Update context with step result
                if step.result:
                    workflow.context[f"step_{step.name}"] = step.result
            
            # Determine workflow status
            failed_steps = [s for s in workflow.steps.values() if s.status == StepStatus.FAILED]
            if failed_steps:
                workflow.status = StepStatus.FAILED
            else:
                workflow.status = StepStatus.COMPLETED
            
            logger.info(f"Workflow {workflow.name} completed with status: {workflow.status}")
            
        except Exception as e:
            workflow.status = StepStatus.FAILED
            logger.error(f"Workflow {workflow.name} failed: {e}")
        
        return {
            'workflow_id': workflow.id,
            'status': workflow.status.value,
            'steps': {
                s.name: {'status': s.status.value, 'error': s.error}
                for s in workflow.steps.values()
            },
            'context': workflow.context
        }
    
    async def _execute_step(self, step: WorkflowStep, context: Dict[str, Any]):
        """Execute a single workflow step"""
        step.status = StepStatus.RUNNING
        step.started_at = datetime.now(timezone.utc)
        
        logger.info(f"Executing step: {step.name}")
        
        retry = 0
        while retry <= step.retry_count:
            try:
                # Execute with timeout
                if asyncio.iscoroutinefunction(step.action):
                    step.result = await asyncio.wait_for(
                        step.action(context),
                        timeout=step.timeout
                    )
                else:
                    step.result = step.action(context)
                
                step.status = StepStatus.COMPLETED
                step.finished_at = datetime.now(timezone.utc)
                logger.info(f"Step {step.name} completed successfully")
                return
                
            except asyncio.TimeoutError:
                step.error = f"Step timed out after {step.timeout}s"
                logger.error(f"Step {step.name} timed out")
                
            except Exception as e:
                step.error = str(e)
                logger.error(f"Step {step.name} failed: {e}")
            
            retry += 1
            if retry <= step.retry_count:
                logger.info(f"Retrying step {step.name} ({retry}/{step.retry_count})")
                await asyncio.sleep(1)
        
        step.status = StepStatus.FAILED
        step.finished_at = datetime.now(timezone.utc)
    
    def _resolve_dependencies(self, workflow: Workflow) -> List[str]:
        """Resolve step execution order using topological sort"""
        visited = set()
        order = []
        
        def visit(step_id: str):
            if step_id in visited:
                return
            visited.add(step_id)
            
            step = workflow.steps.get(step_id)
            if step:
                for dep_id in step.depends_on:
                    visit(dep_id)
                order.append(step_id)
        
        for step_id in workflow.steps:
            visit(step_id)
        
        return order
    
    def get_workflow(self, workflow_id: str) -> Optional[Workflow]:
        """Get workflow by ID"""
        return self._workflows.get(workflow_id)
    
    def list_workflows(self) -> List[Dict]:
        """List all workflows"""
        return [
            {
                'id': w.id,
                'name': w.name,
                'status': w.status.value,
                'steps_count': len(w.steps),
                'created_at': w.created_at.isoformat()
            }
            for w in self._workflows.values()
        ]


# Pre-built workflow templates
def create_auth_escalation_workflow() -> Workflow:
    """Create a workflow for testing authentication and privilege escalation"""
    wf = Workflow(
        id=str(uuid.uuid4()),
        name="Auth & Privilege Escalation Test"
    )
    
    async def authenticate(ctx):
        # Placeholder - would authenticate to target
        return {'token': 'test_token', 'user_id': 'user123'}
    
    async def test_horizontal_access(ctx):
        # Test accessing other users' resources
        return {'idor_findings': []}
    
    async def test_vertical_escalation(ctx):
        # Test accessing admin endpoints
        return {'escalation_findings': []}
    
    auth_step = wf.add_step('authenticate', authenticate)
    wf.add_step('horizontal_access', test_horizontal_access, depends_on=[auth_step])
    wf.add_step('vertical_escalation', test_vertical_escalation, depends_on=[auth_step])
    
    return wf


def create_full_scan_workflow() -> Workflow:
    """Create a comprehensive scan workflow"""
    wf = Workflow(
        id=str(uuid.uuid4()),
        name="Full Security Scan"
    )
    
    async def recon_phase(ctx):
        return {'endpoints': [], 'technologies': []}
    
    async def auth_analysis(ctx):
        return {'findings': []}
    
    async def injection_testing(ctx):
        return {'findings': []}
    
    async def generate_report(ctx):
        return {'report_path': 'reports/latest.json'}
    
    recon = wf.add_step('reconnaissance', recon_phase)
    auth = wf.add_step('auth_analysis', auth_analysis, depends_on=[recon])
    injection = wf.add_step('injection_testing', injection_testing, depends_on=[recon])
    wf.add_step('report_generation', generate_report, depends_on=[auth, injection])
    
    return wf


# Global workflow manager
workflow_manager = WorkflowManager()
workflow_manager.register_template('auth_escalation', create_auth_escalation_workflow)
workflow_manager.register_template('full_scan', create_full_scan_workflow)
