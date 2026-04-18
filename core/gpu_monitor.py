"""
GPU Monitoring Module for REAA
Monitors NVIDIA GPU usage, memory, temperature, and utilization
Dynamic and resilient for different GPU environments
"""

import logging
import platform
from typing import Dict, Any, Optional, List
import subprocess
import re

log = logging.getLogger(__name__)


class GPUMonitor:
    """Dynamic GPU monitoring class with fallbacks for different environments"""
    
    def __init__(self):
        self._available = False
        self._gpu_info = {}
        self._monitoring_method = None
        self._check_gpu_available()
    
    def _check_gpu_available(self) -> bool:
        """Check if NVIDIA GPU is available using multiple methods"""

        if self._try_pynvml():
            self._monitoring_method = "pynvml"
            self._available = True
            log.info("GPU monitoring available via pyNVML (preferred)")
            return True

        if self._try_nvidia_smi():
            self._monitoring_method = "nvidia-smi"
            self._available = True
            log.info("GPU monitoring available via nvidia-smi")
            return True

        if self._try_pytorch_cuda():
            self._monitoring_method = "pytorch"
            self._available = True
            log.info("GPU monitoring available via PyTorch CUDA")
            return True

        if self._try_platform_specific():
            self._monitoring_method = "platform"
            self._available = True
            log.info("GPU monitoring available via platform-specific method")
            return True

        log.warning("GPU monitoring not available - no suitable method found")
        self._available = False
        return False

    def _try_pynvml(self) -> bool:
        """Try to use pyNVML for GPU monitoring"""
        try:
            import pynvml
            pynvml.nvmlInit()
            device_count = pynvml.nvmlDeviceGetCount()
            if device_count > 0:
                handle = pynvml.nvmlDeviceGetHandleByIndex(0)
                gpu_name = pynvml.nvmlDeviceGetName(handle)
                self._gpu_info['name'] = gpu_name
                self._gpu_info['device_count'] = device_count
                pynvml.nvmlShutdown()
                return True
        except ImportError:
            log.debug("pyNVML not available")
        except Exception as e:
            log.debug(f"pyNVML check failed: {e}")
        return False

    def _try_nvidia_smi(self) -> bool:
        """Try to use nvidia-smi for GPU monitoring"""
        try:
            result = subprocess.run(
                ['nvidia-smi', '--query-gpu=name', '--format=csv,noheader'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0 and result.stdout.strip():
                
                gpu_name = result.stdout.strip().split('\n')[0].strip()
                self._gpu_info['name'] = gpu_name
                return True
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
            log.debug(f"nvidia-smi not available: {e}")
        return False
    
    def _try_pytorch_cuda(self) -> bool:
        """Try to use PyTorch CUDA for GPU monitoring"""
        try:
            import torch
            if torch.cuda.is_available():
                gpu_name = torch.cuda.get_device_name(0)
                self._gpu_info['name'] = gpu_name
                self._gpu_info['device_count'] = torch.cuda.device_count()
                return True
        except ImportError:
            log.debug("PyTorch not available")
        except Exception as e:
            log.debug(f"PyTorch CUDA check failed: {e}")
        return False
    
    def _try_platform_specific(self) -> bool:
        """Try platform-specific GPU detection methods"""
        try:
            if platform.system() == "Windows":
              
                result = subprocess.run(
                    ['wmic', 'path', 'win32_VideoController', 'get', 'name'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0 and result.stdout.strip():
                    lines = result.stdout.strip().split('\n')
                    if len(lines) > 1:
                        gpu_name = lines[1].strip()
                        if 'NVIDIA' in gpu_name or 'GeForce' in gpu_name or 'RTX' in gpu_name:
                            self._gpu_info['name'] = gpu_name
                            return True
            elif platform.system() == "Linux":
           
                result = subprocess.run(
                    ['lspci', '-nn', '-d', '::0300'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0 and result.stdout.strip():
                    if 'NVIDIA' in result.stdout:
                      
                        match = re.search(r'NVIDIA\s+[\w\s]+', result.stdout)
                        if match:
                            gpu_name = match.group(0).strip()
                            self._gpu_info['name'] = gpu_name
                            return True
        except Exception as e:
            log.debug(f"Platform-specific GPU detection failed: {e}")
        return False
    
    def is_available(self) -> bool:
        """Check if GPU monitoring is available"""
        return self._available
    
    def get_monitoring_method(self) -> Optional[str]:
        """Get the current monitoring method being used"""
        return self._monitoring_method
    
    def get_gpu_stats(self) -> Dict[str, Any]:
        """
        Get current GPU statistics with fallbacks

        Returns:
            Dict with GPU information including:
            - available: Whether GPU monitoring is available
            - method: Monitoring method used
            - name: GPU name
            - memory_used: Memory used in MB
            - memory_total: Total memory in MB
            - memory_percent: Memory usage percentage
            - utilization: GPU utilization percentage
            - temperature: GPU temperature in Celsius
            - power_usage: Power usage in watts
            - power_limit: Power limit in watts
            - gpu_clock_mhz: GPU graphics clock speed in MHz
            - memory_clock_base_mhz: Base memory clock speed in MHz
            - memory_clock_effective_mhz: Effective memory clock speed in MHz (x2 for GDDR)
            - fan_speed_percent: Fan speed percentage
            - processes: Number of processes using GPU
        """
        if not self._available:
            return {
                "available": False,
                "method": None,
                "error": "GPU monitoring not available"
            }
        

        if self._monitoring_method == "pynvml":
            return self._get_stats_pynvml()

        if self._monitoring_method == "nvidia-smi":
            return self._get_stats_nvidia_smi()
        elif self._monitoring_method == "pytorch":
            return self._get_stats_pytorch()
        elif self._monitoring_method == "platform":
            return self._get_stats_platform()
        else:
            return self._get_stats_fallback()

    def _get_stats_pynvml(self) -> Dict[str, Any]:
        """Get GPU stats using pyNVML (NVML library) - most efficient method"""
        try:
            import pynvml
            pynvml.nvmlInit()

            handle = pynvml.nvmlDeviceGetHandleByIndex(0)


            name = pynvml.nvmlDeviceGetName(handle)


            memory_info = pynvml.nvmlDeviceGetMemoryInfo(handle)
            memory_used_mb = memory_info.used // (1024 * 1024)
            memory_total_mb = memory_info.total // (1024 * 1024)
            memory_percent = round((memory_info.used / memory_info.total) * 100, 2)

         
            utilization = pynvml.nvmlDeviceGetUtilizationRates(handle)
            utilization_percent = utilization.gpu

          
            try:
                temperature = pynvml.nvmlDeviceGetTemperature(handle, pynvml.NVML_TEMPERATURE_GPU)
            except:
                temperature = None


            try:
                power_usage = pynvml.nvmlDeviceGetPowerUsage(handle)
             
                power_usage = power_usage / 1000.0 if power_usage else None
            except:
                power_usage = None

            try:
                power_limit = pynvml.nvmlDeviceGetPowerManagementLimit(handle)
             
                power_limit = power_limit / 1000.0 if power_limit else None
            except:
                power_limit = None

            power_percent = round((power_usage / power_limit) * 100, 2) if power_usage and power_limit else None

           
            try:
                graphics_clock = pynvml.nvmlDeviceGetClockInfo(handle, pynvml.NVML_CLOCK_GRAPHICS)
                gpu_clock_mhz = graphics_clock
            except:
                gpu_clock_mhz = None

       
            try:
                memory_clock = pynvml.nvmlDeviceGetClockInfo(handle, pynvml.NVML_CLOCK_MEM)
              
                memory_clock_base_mhz = memory_clock
                memory_clock_effective_mhz = memory_clock
            except:
                memory_clock_base_mhz = None
                memory_clock_effective_mhz = None

          
            try:
                fan_speed = pynvml.nvmlDeviceGetFanSpeed(handle)
                fan_speed_percent = fan_speed
            except:
                fan_speed_percent = None

          
            try:
                processes = pynvml.nvmlDeviceGetComputeRunningProcesses(handle)
                process_count = len(processes)
            except:
                process_count = None

            pynvml.nvmlShutdown()

            return {
                "available": True,
                "method": "pynvml",
                "name": name,
                "memory_used_mb": memory_used_mb,
                "memory_total_mb": memory_total_mb,
                "memory_percent": memory_percent,
                "utilization_percent": utilization_percent,
                "temperature_c": temperature,
                "power_usage_w": power_usage,
                "power_limit_w": power_limit,
                "power_percent": power_percent,
                "gpu_clock_mhz": gpu_clock_mhz,
                "memory_clock_base_mhz": memory_clock_base_mhz,
                "memory_clock_effective_mhz": memory_clock_effective_mhz,
                "fan_speed_percent": fan_speed_percent,
                "process_count": process_count
            }
        except ImportError:
            log.debug("pyNVML not available, falling back")
            return self._get_stats_fallback()
        except Exception as e:
            log.error(f"Error getting GPU stats via pyNVML: {e}")
            return self._get_stats_fallback()

    def _get_stats_nvidia_smi(self) -> Dict[str, Any]:
        """Get GPU stats using nvidia-smi"""
        try:

            queries = [
                ['nvidia-smi', '--query-gpu=name,memory.used,memory.total,utilization.gpu,temperature.gpu,power.draw,power.limit,clocks.current.graphics,clocks.current.memory,fan.speed', '--format=csv,noheader,nounits'],
                ['nvidia-smi', '--query-gpu=name,memory.used,memory.total,utilization.gpu,temperature.gpu,power.draw,power.limit', '--format=csv,noheader,nounits'],
                ['nvidia-smi', '--query-gpu=name,memory.used,memory.total,utilization.gpu,temperature.gpu', '--format=csv,noheader,nounits'],
            ]
            
            for query in queries:
                try:
                    result = subprocess.run(
                        query,
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    
                    if result.returncode == 0 and result.stdout.strip():
                        values = result.stdout.strip().split(',')
                        name = values[0].strip() if len(values) > 0 else "Unknown"
                        memory_used = int(values[1].strip()) if len(values) > 1 else 0
                        memory_total = int(values[2].strip()) if len(values) > 2 else 0
                        utilization = int(values[3].strip()) if len(values) > 3 else 0
                        temperature = int(values[4].strip()) if len(values) > 4 else 0
                        power_usage = float(values[5].strip()) if len(values) > 5 else 0
                        power_limit = float(values[6].strip()) if len(values) > 6 else 0
                        graphics_clock_mhz = int(values[7].strip()) if len(values) > 7 else 0
                        memory_clock_base_mhz = int(values[8].strip()) if len(values) > 8 else 0
                        fan_speed_percent = int(values[9].strip()) if len(values) > 9 else None


                        
                        memory_clock_effective_mhz = memory_clock_base_mhz * 2


                        try:
                            process_result = subprocess.run(
                                ['nvidia-smi', '--query-compute-apps=pid', '--format=csv,noheader'],
                                capture_output=True,
                                text=True,
                                timeout=5
                            )
                            processes = len([line for line in process_result.stdout.strip().split('\n') if line.strip()])
                        except:
                            processes = 0

                        return {
                            "available": True,
                            "method": "nvidia-smi",
                            "name": name,
                            "memory_used_mb": memory_used,
                            "memory_total_mb": memory_total,
                            "memory_percent": round((memory_used / memory_total) * 100, 2) if memory_total > 0 else 0,
                            "utilization_percent": utilization,
                            "temperature_c": temperature,
                            "power_usage_w": power_usage,
                            "power_limit_w": power_limit,
                            "power_percent": round((power_usage / power_limit) * 100, 2) if power_limit > 0 else 0,
                            "gpu_clock_mhz": graphics_clock_mhz,
                            "memory_clock_base_mhz": memory_clock_base_mhz,
                            "memory_clock_effective_mhz": memory_clock_effective_mhz,
                            "fan_speed_percent": fan_speed_percent,
                            "process_count": processes
                        }
                except Exception as e:
                    log.debug(f"Query format failed: {query}, trying next format")
                    continue
            
          
            return self._get_stats_fallback()
            
        except Exception as e:
            log.error(f"Error getting GPU stats via nvidia-smi: {e}")
            return self._get_stats_fallback()
    
    def _get_stats_pytorch(self) -> Dict[str, Any]:
        """Get GPU stats using PyTorch"""
        try:
            import torch
            if not torch.cuda.is_available():
                return self._get_stats_fallback()

            device = torch.cuda.current_device()

            return {
                "available": True,
                "method": "pytorch",
                "name": torch.cuda.get_device_name(device),
                "memory_used_mb": torch.cuda.memory_allocated(device) // (1024 * 1024),
                "memory_total_mb": torch.cuda.get_device_properties(device).total_memory // (1024 * 1024),
                "memory_percent": round((torch.cuda.memory_allocated(device) / torch.cuda.get_device_properties(device).total_memory) * 100, 2),
                "utilization_percent": None,
                "temperature_c": None,
                "power_usage_w": None,
                "power_limit_w": None,
                "power_percent": None,
                "gpu_clock_mhz": None,
                "memory_clock_base_mhz": None,
                "memory_clock_effective_mhz": None,
                "fan_speed_percent": None,
                "process_count": None
            }
        except Exception as e:
            log.error(f"Error getting GPU stats via PyTorch: {e}")
            return self._get_stats_fallback()
    
    def _get_stats_platform(self) -> Dict[str, Any]:
        """Get GPU stats using platform-specific methods"""
        return {
            "available": True,
            "method": "platform",
            "name": self._gpu_info.get('name', 'Unknown GPU'),
            "memory_used_mb": None,
            "memory_total_mb": None,
            "memory_percent": None,
            "utilization_percent": None,
            "temperature_c": None,
            "power_usage_w": None,
            "power_limit_w": None,
            "power_percent": None,
            "gpu_clock_mhz": None,
            "memory_clock_base_mhz": None,
            "memory_clock_effective_mhz": None,
            "fan_speed_percent": None,
            "process_count": None,
            "note": "Platform detection only - limited stats available"
        }

    def _get_stats_fallback(self) -> Dict[str, Any]:
        """Fallback stats when detailed monitoring is not available"""
        return {
            "available": True,
            "method": "fallback",
            "name": self._gpu_info.get('name', 'Unknown GPU'),
            "memory_used_mb": None,
            "memory_total_mb": None,
            "memory_percent": None,
            "utilization_percent": None,
            "temperature_c": None,
            "power_usage_w": None,
            "power_limit_w": None,
            "power_percent": None,
            "gpu_clock_mhz": None,
            "memory_clock_base_mhz": None,
            "memory_clock_effective_mhz": None,
            "fan_speed_percent": None,
            "process_count": None,
            "note": "GPU detected but detailed monitoring not available"
        }
    
    def get_detailed_info(self) -> Dict[str, Any]:
        """
        Get detailed GPU information
        
        Returns:
            Dict with detailed GPU information
        """
        if not self._available:
            return {
                "available": False,
                "method": None,
                "error": "GPU monitoring not available"
            }
        

        basic_stats = self.get_gpu_stats()
        detailed_info = basic_stats.copy()
        
       
        detailed_info['platform'] = platform.system()
        detailed_info['platform_version'] = platform.version()
        
       
        detailed_info['monitoring_method'] = self._monitoring_method
        
        return detailed_info



_gpu_monitor: Optional[GPUMonitor] = None


def get_gpu_monitor() -> GPUMonitor:
    """Get or create the global GPU monitor instance"""
    global _gpu_monitor
    if _gpu_monitor is None:
        _gpu_monitor = GPUMonitor()
    return _gpu_monitor
