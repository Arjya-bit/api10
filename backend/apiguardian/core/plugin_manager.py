"""Plugin Manager - Auto-discovers and loads plugins"""
import importlib
import pkgutil
import inspect
import logging
from typing import Dict, List, Type, Any, Optional
from pathlib import Path

logger = logging.getLogger(__name__)


class BasePlugin:
    """Base class for all plugins"""
    plugin_type: str = "base"
    plugin_name: str = "unnamed"
    description: str = ""
    version: str = "1.0.0"
    enabled: bool = True
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.results = []
        
    async def execute(self, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Execute the plugin - override in subclasses"""
        raise NotImplementedError("Plugins must implement execute()")
    
    def validate_config(self) -> bool:
        """Validate plugin configuration"""
        return True


class AnalyzerPlugin(BasePlugin):
    """Base class for analyzer plugins"""
    plugin_type = "analyzer"
    
    async def analyze(self, target: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze target and return findings"""
        raise NotImplementedError("Analyzers must implement analyze()")
    
    async def execute(self, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        target = context.get('target', '')
        return await self.analyze(target, context)


class FuzzerPlugin(BasePlugin):
    """Base class for fuzzer plugins"""
    plugin_type = "fuzzer"
    destructive = False  # Default to non-destructive
    
    async def fuzz(self, target: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Fuzz target and return findings"""
        raise NotImplementedError("Fuzzers must implement fuzz()")
    
    async def execute(self, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        # Safety check for destructive mode
        if self.destructive and not context.get('enable_destructive', False):
            logger.warning(f"Skipping destructive fuzzer {self.plugin_name} - destructive mode not enabled")
            return []
        target = context.get('target', '')
        return await self.fuzz(target, context)


class ReconPlugin(BasePlugin):
    """Base class for recon plugins"""
    plugin_type = "recon"
    
    async def recon(self, target: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Perform reconnaissance and return discovered assets/endpoints"""
        raise NotImplementedError("Recon plugins must implement recon()")
    
    async def execute(self, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        target = context.get('target', '')
        result = await self.recon(target, context)
        return [result] if result else []


class ReporterPlugin(BasePlugin):
    """Base class for reporter plugins"""
    plugin_type = "reporter"
    
    async def generate(self, findings: List[Dict], context: Dict[str, Any]) -> str:
        """Generate report and return path/content"""
        raise NotImplementedError("Reporters must implement generate()")
    
    async def execute(self, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = context.get('findings', [])
        result = await self.generate(findings, context)
        return [{'report_path': result}] if result else []


class PluginManager:
    """Manages plugin discovery, loading, and execution"""
    
    def __init__(self):
        self._plugins: Dict[str, Dict[str, Type[BasePlugin]]] = {
            'analyzer': {},
            'fuzzer': {},
            'recon': {},
            'reporter': {}
        }
        self._instances: Dict[str, BasePlugin] = {}
        
    def discover_plugins(self, package_path: str = "apiguardian.modules"):
        """Auto-discover plugins from package"""
        try:
            package = importlib.import_module(package_path)
            package_dir = Path(package.__file__).parent
            
            for subdir in ['analyzers', 'fuzzers', 'recon', 'scanners']:
                subpackage_path = f"{package_path}.{subdir}"
                try:
                    subpackage = importlib.import_module(subpackage_path)
                    self._scan_package(subpackage, subpackage_path)
                except ImportError as e:
                    logger.debug(f"Could not import {subpackage_path}: {e}")
                    
        except ImportError as e:
            logger.error(f"Could not import plugin package {package_path}: {e}")
    
    def _scan_package(self, package, package_path: str):
        """Scan a package for plugin classes"""
        for importer, modname, ispkg in pkgutil.walk_packages(
            path=package.__path__,
            prefix=f"{package_path}."
        ):
            try:
                module = importlib.import_module(modname)
                self._register_module_plugins(module)
            except ImportError as e:
                logger.warning(f"Could not import module {modname}: {e}")
    
    def _register_module_plugins(self, module):
        """Register plugin classes from a module"""
        for name, obj in inspect.getmembers(module, inspect.isclass):
            if self._is_plugin_class(obj):
                self.register_plugin(obj)
    
    def _is_plugin_class(self, cls) -> bool:
        """Check if class is a valid plugin"""
        if cls in (BasePlugin, AnalyzerPlugin, FuzzerPlugin, ReconPlugin, ReporterPlugin):
            return False
        return (
            hasattr(cls, 'plugin_type') and
            hasattr(cls, 'plugin_name') and
            issubclass(cls, BasePlugin)
        )
    
    def register_plugin(self, plugin_cls: Type[BasePlugin]):
        """Register a plugin class"""
        plugin_type = plugin_cls.plugin_type
        plugin_name = plugin_cls.plugin_name
        
        if plugin_type in self._plugins:
            self._plugins[plugin_type][plugin_name] = plugin_cls
            logger.info(f"Registered {plugin_type} plugin: {plugin_name}")
        else:
            logger.warning(f"Unknown plugin type: {plugin_type}")
    
    def get_plugin(self, plugin_type: str, plugin_name: str, config: Dict = None) -> Optional[BasePlugin]:
        """Get an instance of a plugin"""
        key = f"{plugin_type}:{plugin_name}"
        
        if key not in self._instances:
            plugin_cls = self._plugins.get(plugin_type, {}).get(plugin_name)
            if plugin_cls:
                self._instances[key] = plugin_cls(config)
            else:
                return None
        
        return self._instances.get(key)
    
    def get_plugins_by_type(self, plugin_type: str) -> List[Type[BasePlugin]]:
        """Get all plugins of a specific type"""
        return list(self._plugins.get(plugin_type, {}).values())
    
    def get_all_plugins(self) -> Dict[str, Dict[str, Type[BasePlugin]]]:
        """Get all registered plugins"""
        return self._plugins
    
    def list_plugins(self) -> List[Dict[str, str]]:
        """List all registered plugins with metadata"""
        result = []
        for plugin_type, plugins in self._plugins.items():
            for name, cls in plugins.items():
                result.append({
                    'type': plugin_type,
                    'name': name,
                    'description': cls.description,
                    'version': cls.version,
                    'enabled': cls.enabled
                })
        return result


# Global plugin manager instance
plugin_manager = PluginManager()
