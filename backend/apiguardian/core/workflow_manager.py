"""Workflow Manager - Orchestrate complex scan workflows"""
import logging
import asyncio
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class StepStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class WorkflowStep:
    """Individual step in a workflow"""
    id: str
    name: str
    plugin_type: str
    plugin_name: str
    config: Dict[str, Any] = field(default_factory=dict)
    depends_on: List[str] = field(default_factory=list)
    condition: Optional[str] = None  # e.g., "findings.critical > 0"
    status: StepStatus = StepStatus.PENDING
    result: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None


@dataclass
class Workflow:
    """Workflow definition and state"""
    id: str
    name: str
    description: str = ""
    steps: List[WorkflowStep] = field(default_factory=list)
    status: str = "pending"
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    context: Dict[str, Any] = field(default_factory=dict)
    
    def add_step(self, step: WorkflowStep):
        self.steps.append(step)
    
    def get_step(self, step_id: str) -> Optional[WorkflowStep]:
        for step in self.steps:
            if step.id == step_id:
                return step
        return None
    
    def get_ready_steps(self) -> List[WorkflowStep]:
        """Get steps that are ready to execute"""
        ready = []
        for step in self.steps:
            if step.status != StepStatus.PENDING:
                continue
            # Check dependencies
            deps_met = all(
                self.get_step(dep_id).status == StepStatus.COMPLETED
                for dep_id in step.depends_on
                if self.get_step(dep_id)
            )
            if deps_met:
                ready.append(step)
        return ready


class WorkflowManager:
    """Manages workflow creation, execution, and monitoring"""
    
    def __init__(self):
        self.workflows: Dict[str, Workflow] = {}
        self.templates: Dict[str, Dict] = self._load_templates()
    
    def _load_templates(self) -> Dict[str, Dict]:
        """Load built-in workflow templates"""
        return {
            'quick_scan': {
                'name': 'Quick Security Scan',
                'description': 'Fast scan with essential checks',
                'steps': [
                    {'name': 'Recon', 'plugin_type': 'recon', 'plugin_name': 'endpoint_discovery'},
                    {'name': 'JWT Analysis', 'plugin_type': 'analyzer', 'plugin_name': 'jwt_analyzer'},
                    {'name': 'Auth Check', 'plugin_type': 'analyzer', 'plugin_name': 'auth_analyzer'},
                ]
            },
            'full_scan': {
                'name': 'Full Security Assessment',
                'description': 'Comprehensive security scan',
                'steps': [
                    {'name': 'OpenAPI Discovery', 'plugin_type': 'recon', 'plugin_name': 'openapi_scanner'},
                    {'name': 'Endpoint Discovery', 'plugin_type': 'recon', 'plugin_name': 'endpoint_discovery'},
                    {'name': 'JWT Analysis', 'plugin_type': 'analyzer', 'plugin_name': 'jwt_analyzer', 'depends_on': ['step_0', 'step_1']},
                    {'name': 'IDOR Detection', 'plugin_type': 'analyzer', 'plugin_name': 'idor_detector', 'depends_on': ['step_0', 'step_1']},
                    {'name': 'Auth Analysis', 'plugin_type': 'analyzer', 'plugin_name': 'auth_analyzer', 'depends_on': ['step_0']},
                    {'name': 'Rate Limit Check', 'plugin_type': 'analyzer', 'plugin_name': 'rate_limit_analyzer', 'depends_on': ['step_0']},
                    {'name': 'Replay Attack Check', 'plugin_type': 'analyzer', 'plugin_name': 'replay_attack_detector', 'depends_on': ['step_2']},
                    {'name': 'Cloud Security', 'plugin_type': 'analyzer', 'plugin_name': 'cloud_analyzer', 'depends_on': ['step_0']},
                    {'name': 'Payload Fuzzing', 'plugin_type': 'fuzzer', 'plugin_name': 'payload_fuzzer', 'depends_on': ['step_3', 'step_4']},
                    {'name': 'Schema Fuzzing', 'plugin_type': 'fuzzer', 'plugin_name': 'schema_fuzzer', 'depends_on': ['step_0']},
                ]
            },
            'api_pentest': {
                'name': 'API Penetration Test',
                'description': 'Aggressive API security testing',
                'steps': [
                    {'name': 'Full Recon', 'plugin_type': 'recon', 'plugin_name': 'openapi_scanner'},
                    {'name': 'Endpoint Enum', 'plugin_type': 'recon', 'plugin_name': 'endpoint_discovery'},
                    {'name': 'All Analyzers', 'plugin_type': 'analyzer', 'plugin_name': 'all', 'depends_on': ['step_0', 'step_1']},
                    {'name': 'Schema Fuzz', 'plugin_type': 'fuzzer', 'plugin_name': 'schema_fuzzer', 'depends_on': ['step_0']},
                    {'name': 'Mutation Fuzz', 'plugin_type': 'fuzzer', 'plugin_name': 'mutation_fuzzer', 'depends_on': ['step_2']},
                    {'name': 'GraphQL Fuzz', 'plugin_type': 'fuzzer', 'plugin_name': 'graphql_fuzzer', 'depends_on': ['step_0']},
                    {'name': 'Payload Fuzz', 'plugin_type': 'fuzzer', 'plugin_name': 'payload_fuzzer', 'depends_on': ['step_2']},
                ]
            },
            'compliance_check': {
                'name': 'Compliance Check',
                'description': 'Security compliance verification',
                'steps': [
                    {'name': 'Recon', 'plugin_type': 'recon', 'plugin_name': 'openapi_scanner'},
                    {'name': 'Auth Security', 'plugin_type': 'analyzer', 'plugin_name': 'auth_analyzer'},
                    {'name': 'Rate Limiting', 'plugin_type': 'analyzer', 'plugin_name': 'rate_limit_analyzer'},
                    {'name': 'Cloud Config', 'plugin_type': 'analyzer', 'plugin_name': 'cloud_analyzer'},
                ]
            }
        }
    
    def create_workflow(
        self,
        name: str,
        steps: List[Dict[str, Any]] = None,
        template: str = None,
        context: Dict[str, Any] = None
    ) -> Workflow:
        """Create a new workflow"""
        workflow_id = str(uuid.uuid4())
        
        if template and template in self.templates:
            tmpl = self.templates[template]
            name = tmpl['name']
            steps = tmpl['steps']
        
        workflow = Workflow(
            id=workflow_id,
            name=name,
            context=context or {}
        )
        
        # Add steps
        for i, step_def in enumerate(steps or []):
            step = WorkflowStep(
                id=f"step_{i}",
                name=step_def.get('name', f'Step {i}'),
                plugin_type=step_def.get('plugin_type', 'analyzer'),
                plugin_name=step_def.get('plugin_name', ''),
                config=step_def.get('config', {}),
                depends_on=step_def.get('depends_on', []),
                condition=step_def.get('condition')
            )
            workflow.add_step(step)
        
        self.workflows[workflow_id] = workflow
        logger.info(f"Created workflow: {workflow_id} - {name}")
        
        return workflow
    
    def get_workflow(self, workflow_id: str) -> Optional[Workflow]:
        return self.workflows.get(workflow_id)
    
    def list_workflows(self) -> List[Dict]:
        return [
            {
                'id': w.id,
                'name': w.name,
                'status': w.status,
                'steps_total': len(w.steps),
                'steps_completed': sum(1 for s in w.steps if s.status == StepStatus.COMPLETED),
                'created_at': w.created_at.isoformat()
            }
            for w in self.workflows.values()
        ]
    
    def list_templates(self) -> List[Dict]:
        return [
            {'id': tid, 'name': t['name'], 'description': t['description']}
            for tid, t in self.templates.items()
        ]
    
    async def execute_workflow(
        self,
        workflow_id: str,
        engine,
        on_step_complete: Callable = None
    ) -> Workflow:
        """Execute a workflow"""
        workflow = self.workflows.get(workflow_id)
        if not workflow:
            raise ValueError(f"Workflow not found: {workflow_id}")
        
        workflow.status = 'running'
        workflow.started_at = datetime.now(timezone.utc)
        
        try:
            while True:
                ready_steps = workflow.get_ready_steps()
                if not ready_steps:
                    # Check if all steps are done
                    all_done = all(
                        s.status in [StepStatus.COMPLETED, StepStatus.FAILED, StepStatus.SKIPPED]
                        for s in workflow.steps
                    )
                    if all_done:
                        break
                    else:
                        # Some steps still pending but blocked
                        logger.warning("Workflow has blocked steps")
                        break
                
                # Execute ready steps in parallel
                tasks = [
                    self._execute_step(workflow, step, engine)
                    for step in ready_steps
                ]
                await asyncio.gather(*tasks)
                
                # Callback
                if on_step_complete:
                    for step in ready_steps:
                        on_step_complete(workflow, step)
            
            workflow.status = 'completed'
            
        except Exception as e:
            workflow.status = 'failed'
            logger.error(f"Workflow failed: {e}")
            raise
        
        finally:
            workflow.finished_at = datetime.now(timezone.utc)
        
        return workflow
    
    async def _execute_step(self, workflow: Workflow, step: WorkflowStep, engine):
        """Execute a single workflow step"""
        step.status = StepStatus.RUNNING
        step.started_at = datetime.now(timezone.utc)
        
        try:
            # Check condition
            if step.condition and not self._evaluate_condition(step.condition, workflow.context):
                step.status = StepStatus.SKIPPED
                logger.info(f"Step skipped (condition not met): {step.name}")
                return
            
            # Get plugin and execute
            from apiguardian.core.plugin_manager import plugin_manager
            
            if step.plugin_name == 'all':
                # Run all plugins of type
                plugins = plugin_manager.get_plugins_by_type(step.plugin_type)
                results = []
                for plugin_cls in plugins:
                    plugin = plugin_cls(step.config)
                    result = await plugin.execute(workflow.context)
                    results.extend(result)
                step.result = {'findings': results}
            else:
                plugin = plugin_manager.get_plugin(
                    step.plugin_type,
                    step.plugin_name,
                    step.config
                )
                if plugin:
                    result = await plugin.execute(workflow.context)
                    step.result = {'findings': result}
                else:
                    raise ValueError(f"Plugin not found: {step.plugin_type}/{step.plugin_name}")
            
            step.status = StepStatus.COMPLETED
            logger.info(f"Step completed: {step.name}")
            
        except Exception as e:
            step.status = StepStatus.FAILED
            step.error = str(e)
            logger.error(f"Step failed: {step.name} - {e}")
        
        finally:
            step.finished_at = datetime.now(timezone.utc)
    
    def _evaluate_condition(self, condition: str, context: Dict) -> bool:
        """Evaluate a step condition safely without using eval()"""
        import re
        try:
            # Parse simple conditions like "findings.critical > 0"
            # Support format: "key.subkey operator value"
            match = re.match(r'^(\w+(?:\.\w+)*)\s*(==|!=|>=|<=|>|<)\s*(.+)$', condition.strip())
            if not match:
                logger.warning(f"Could not parse condition: {condition}")
                return True

            key_path, operator, value_str = match.groups()

            # Navigate to the value in context
            current = context
            for key in key_path.split('.'):
                if isinstance(current, dict):
                    current = current.get(key, 0)
                else:
                    current = getattr(current, key, 0)

            # Parse the comparison value
            value_str = value_str.strip()
            if value_str.lower() == 'true':
                compare_value = True
            elif value_str.lower() == 'false':
                compare_value = False
            elif value_str.startswith('"') or value_str.startswith("'"):
                compare_value = value_str[1:-1]
            else:
                try:
                    compare_value = int(value_str)
                except ValueError:
                    try:
                        compare_value = float(value_str)
                    except ValueError:
                        compare_value = value_str

            # Perform comparison
            if operator == '==':
                return current == compare_value
            elif operator == '!=':
                return current != compare_value
            elif operator == '>':
                return current > compare_value
            elif operator == '<':
                return current < compare_value
            elif operator == '>=':
                return current >= compare_value
            elif operator == '<=':
                return current <= compare_value

            return True
        except Exception as e:
            logger.warning(f"Condition evaluation failed for '{condition}': {e}")
            return True  # Default to running if condition fails


# Global instance
workflow_manager = WorkflowManager()
