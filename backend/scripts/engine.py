import asyncio
import importlib.util
import os
import inspect
from typing import Optional, List, Dict, Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class ScriptCategory(Enum):
    """Script categories for organization and filtering"""
    VULNERABILITY = "vulnerability"
    ENUMERATION = "enumeration"
    BRUTE_FORCE = "brute_force"
    CREDENTIAL_CHECK = "credential_check"
    VERSION_DETECTION = "version_detection"
    PROTOCOL_ANALYSIS = "protocol_analysis"
    INFO_GATHERING = "info_gathering"
    EXPLOIT_ATTEMPT = "exploit_attempt"
    GENERAL = "general"


class ScriptSeverity(Enum):
    """Severity levels for findings"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class ScriptResult:
    name: str
    category: str
    output: str = ""
    findings: list = field(default_factory=list)
    risk: str = "info"
    execution_time: float = 0.0
    status: str = "success"  # success, timeout, error
    error: str = ""
    timestamp: str = ""
    target: str = ""
    port: int = None

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()


class ScriptEngine:
    def __init__(self, scripts_dir: str = None, timeout: float = 10.0):
        self.scripts_dir = scripts_dir or os.path.join(os.path.dirname(__file__))
        self.timeout = timeout
        self._scripts = {}
        self._execution_history = []
        self._progress_callbacks = []
        self._load_scripts()

    def _load_scripts(self):
        """Load all scripts from directory with validation"""
        if not os.path.exists(self.scripts_dir):
            print(f"[!] Scripts directory not found: {self.scripts_dir}")
            return

        for filename in os.listdir(self.scripts_dir):
            if filename.endswith('.py') and not filename.startswith('_'):
                try:
                    script_path = os.path.join(self.scripts_dir, filename)
                    spec = importlib.util.spec_from_file_location(
                        filename[:-3],
                        script_path
                    )
                    if spec is None or spec.loader is None:
                        continue
                    
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    
                    # Validate required attributes
                    if not hasattr(module, 'run'):
                        print(f"[!] Script {filename} missing 'run' function")
                        continue
                    
                    if not callable(getattr(module, 'run')):
                        print(f"[!] Script {filename} 'run' is not callable")
                        continue
                    
                    script_name = filename[:-3]
                    self._scripts[script_name] = module
                    print(f"[+] Loaded script: {script_name}")

                except Exception as e:
                    print(f"[!] Failed to load script {filename}: {e}")

    def register_progress_callback(self, callback: Callable):
        """Register callback for progress updates"""
        self._progress_callbacks.append(callback)

    def _emit_progress(self, message: str, data: Dict = None):
        """Emit progress event to all registered callbacks"""
        for callback in self._progress_callbacks:
            try:
                callback({'message': message, 'data': data or {}})
            except Exception as e:
                print(f"[!] Progress callback error: {e}")

    def list_scripts(self) -> List[Dict]:
        """Get metadata for all loaded scripts"""
        scripts = []
        for name, mod in self._scripts.items():
            script_info = {
                'name': name,
                'category': getattr(mod, 'CATEGORY', 'general'),
                'description': getattr(mod, 'DESCRIPTION', ''),
                'ports': getattr(mod, 'PORTS', []),
                'tags': getattr(mod, 'TAGS', []),
                'risk_level': getattr(mod, 'RISK_LEVEL', 'info'),
                'timeout': getattr(mod, 'TIMEOUT', self.timeout),
                'author': getattr(mod, 'AUTHOR', ''),
                'version': getattr(mod, 'VERSION', '1.0'),
            }
            scripts.append(script_info)
        return scripts

    def filter_scripts(self, category: str = None, ports: List[int] = None, tags: List[str] = None) -> List[str]:
        """Filter scripts by category, ports, or tags"""
        filtered = []
        for name, mod in self._scripts.items():
            if category and getattr(mod, 'CATEGORY', 'general') != category:
                continue
            if ports:
                script_ports = getattr(mod, 'PORTS', [])
                if script_ports and not any(p in script_ports for p in ports):
                    continue
            if tags:
                script_tags = getattr(mod, 'TAGS', [])
                if not any(tag in script_tags for tag in tags):
                    continue
            filtered.append(name)
        return filtered

    async def run_script(self, name: str, target: str, port: int = None, 
                        timeout: float = None) -> Optional[ScriptResult]:
        """Run a single script with timeout and error handling"""
        if name not in self._scripts:
            return ScriptResult(
                name=name, category='error', 
                status='error', error=f"Script '{name}' not found",
                target=target, port=port
            )

        module = self._scripts[name]
        script_timeout = timeout or getattr(module, 'TIMEOUT', self.timeout)
        start_time = datetime.now()

        self._emit_progress(f"Starting script: {name}", {'script': name})

        try:
            # Run with timeout
            result = await asyncio.wait_for(
                module.run(target, port),
                timeout=script_timeout
            )

            execution_time = (datetime.now() - start_time).total_seconds()
            script_result = ScriptResult(
                name=name,
                category=getattr(module, 'CATEGORY', 'general'),
                output=getattr(result, 'output', str(result)),
                findings=getattr(result, 'findings', []),
                risk=getattr(result, 'risk', 'info'),
                execution_time=execution_time,
                status='success',
                target=target,
                port=port
            )

            self._emit_progress(f"Completed script: {name}", 
                              {'script': name, 'execution_time': execution_time})
            self._execution_history.append(script_result)
            return script_result

        except asyncio.TimeoutError:
            execution_time = (datetime.now() - start_time).total_seconds()
            script_result = ScriptResult(
                name=name,
                category=getattr(module, 'CATEGORY', 'general'),
                output=f"Script timed out after {script_timeout}s",
                findings=[],
                risk='info',
                execution_time=execution_time,
                status='timeout',
                target=target,
                port=port
            )
            self._emit_progress(f"Timeout: {name}", {'script': name})
            self._execution_history.append(script_result)
            return script_result

        except Exception as e:
            execution_time = (datetime.now() - start_time).total_seconds()
            script_result = ScriptResult(
                name=name,
                category='error',
                output=f"Execution failed: {str(e)}",
                findings=[],
                risk='info',
                execution_time=execution_time,
                status='error',
                error=str(e),
                target=target,
                port=port
            )
            self._emit_progress(f"Error: {name}", {'script': name, 'error': str(e)})
            self._execution_history.append(script_result)
            return script_result

    async def run_all(self, target: str, port: int = None, 
                     category: str = None, parallel: bool = True,
                     timeout: float = None) -> List[ScriptResult]:
        """
        Run all scripts (or filtered subset) with optional parallelization
        
        Args:
            target: Target IP/hostname
            port: Optional specific port
            category: Filter by category
            parallel: Run scripts concurrently
            timeout: Override default timeout
        """
        # Filter scripts
        scripts_to_run = self._scripts.items()
        
        if category:
            filtered_names = self.filter_scripts(category=category)
            scripts_to_run = [(name, self._scripts[name]) for name in filtered_names]

        if port:
            scripts_to_run = [
                (name, mod) for name, mod in scripts_to_run
                if not getattr(mod, 'PORTS', []) or port in getattr(mod, 'PORTS', [])
            ]

        self._emit_progress(f"Running {len(scripts_to_run)} scripts", 
                           {'count': len(scripts_to_run), 'target': target})

        if parallel:
            # Run scripts concurrently
            tasks = [
                self.run_script(name, target, port, timeout)
                for name, _ in scripts_to_run
            ]
            results = await asyncio.gather(*tasks, return_exceptions=False)
            results = [r for r in results if isinstance(r, ScriptResult)]
        else:
            # Run scripts sequentially
            results = []
            for name, _ in scripts_to_run:
                result = await self.run_script(name, target, port, timeout)
                if result:
                    results.append(result)

        self._emit_progress(f"Completed all scripts", 
                           {'count': len(results), 'target': target})
        return results

    def get_execution_history(self, limit: int = 100) -> List[ScriptResult]:
        """Get recent script execution history"""
        return self._execution_history[-limit:]

    def clear_history(self):
        """Clear execution history"""
        self._execution_history.clear()

    def get_statistics(self) -> Dict:
        """Get statistics about script execution"""
        if not self._execution_history:
            return {'total': 0, 'successful': 0, 'failed': 0, 'avg_time': 0}

        total = len(self._execution_history)
        successful = len([r for r in self._execution_history if r.status == 'success'])
        failed = len([r for r in self._execution_history if r.status == 'error'])
        timeout = len([r for r in self._execution_history if r.status == 'timeout'])
        avg_time = sum(r.execution_time for r in self._execution_history) / total if total > 0 else 0

        return {
            'total': total,
            'successful': successful,
            'failed': failed,
            'timeout': timeout,
            'avg_execution_time': round(avg_time, 2),
        }
