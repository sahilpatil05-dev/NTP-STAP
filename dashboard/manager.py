"""
NTP-SCTAP Dashboard State and System Monitoring Manager.

Manages application state, active WebSocket connections, receiver lifecycle,
and gathers system health metrics in a background thread.
"""

import os
import sys
import time
import ctypes
import threading
import platform
from pathlib import Path
from typing import Any, Dict, Optional

from config.settings import get_config
from database.manager import get_db
from utils.logger import get_logger
from crypto.engine import CryptoEngine
from receiver.manager import ReceiverManager

logger = get_logger("dashboard.manager")

# Windows API Structures for System Monitoring
class FILETIME(ctypes.Structure):
    _fields_ = [("dwLowDateTime", ctypes.c_uint), ("dwHighDateTime", ctypes.c_uint)]

def _ft_to_int(ft: FILETIME) -> int:
    return (ft.dwHighDateTime << 32) + ft.dwLowDateTime

class MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [
        ("dwLength", ctypes.c_ulong),
        ("dwMemoryLoad", ctypes.c_ulong),
        ("ullTotalPhys", ctypes.c_ulonglong),
        ("ullAvailPhys", ctypes.c_ulonglong),
        ("ullTotalPageFile", ctypes.c_ulonglong),
        ("ullAvailPageFile", ctypes.c_ulonglong),
        ("ullTotalVirtual", ctypes.c_ulonglong),
        ("ullAvailVirtual", ctypes.c_ulonglong),
        ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
    ]


class DashboardStateManager:
    """Manages dashboard state, receiver thread lifecycle, and monitoring metrics."""

    def __init__(self) -> None:
        self.cfg = get_config()
        self.db = get_db()
        self.connected_clients = 0
        self.client_lock = threading.Lock()
        
        # Crypto and receiver state
        self.current_password: str = "strong-password"  # default placeholder
        self.receiver_manager: Optional[ReceiverManager] = None
        self.receiver_lock = threading.Lock()
        
        # Monitoring thread lifecycle
        self._monitor_thread: Optional[threading.Thread] = None
        self._monitor_running = False
        self._monitor_lock = threading.Lock()
        self._stop_event = threading.Event()
        
        # Latest gathered metrics cache
        self.metrics_cache: Dict[str, Any] = {
            "cpu_usage": 0.0,
            "memory_usage": 0.0,
            "db_status": "healthy",
            "db_size_bytes": 0,
            "connected_clients": 0,
            "receiver_running": False,
            "packets_per_second": 0.0,
            "system_health": "healthy"
        }
        self._metrics_lock = threading.Lock()
        
        # Variables for CPU calculation delta
        self._last_idle_time = 0
        self._last_kernel_time = 0
        self._last_user_time = 0
        
        # Variables for throughput calculation
        self._last_packet_count = 0
        self._last_time = time.time()

    def start_receiver(self, password: str, message_callback: Optional[Any] = None) -> bool:
        """Start the background receiver manager with the specified password."""
        with self.receiver_lock:
            if self.receiver_manager is not None:
                logger.warning("Receiver is already running; stopping previous instance first.")
                try:
                    self.receiver_manager.stop()
                except Exception as e:
                    logger.error("Failed to stop running receiver: %s", e)
            
            try:
                self.current_password = password
                crypto = CryptoEngine(password=password)
                self.receiver_manager = ReceiverManager(
                    crypto_engine=crypto,
                    bind_port=self.cfg.NTP_LISTEN_PORT,
                    message_callback=message_callback
                )
                self.receiver_manager.start()
                logger.info("Background UDP receiver started successfully via DashboardManager")
                return True
            except Exception as e:
                logger.error("Failed to start UDP receiver: %s", e)
                self.receiver_manager = None
                return False

    def stop_receiver(self) -> bool:
        """Stop the background receiver manager."""
        with self.receiver_lock:
            if self.receiver_manager is None:
                logger.info("Receiver is not running; nothing to stop.")
                return True
            
            try:
                self.receiver_manager.stop()
                self.receiver_manager = None
                logger.info("Background UDP receiver stopped cleanly via DashboardManager")
                return True
            except Exception as e:
                logger.error("Error stopping receiver: %s", e)
                return False

    # ✅ BUG-032 FIX: Add is_monitoring_running() method
    def is_monitoring_running(self) -> bool:
        """Check if the system monitoring thread is running."""
        with self._monitor_lock:
            return bool(self._monitor_running)

    # ✅ BUG-033 FIX: Return actual boolean instead of mock object
    # Check _running flag FIRST (before is_running method) to avoid MagicMock always returning True
    def is_receiver_running(self) -> bool:
        """Check if the receiver thread is active."""
        with self.receiver_lock:
            if self.receiver_manager is None:
                return False

            # First check the receiver._running state (works for production and mocks)
            try:
                return bool(getattr(self.receiver_manager.receiver, "_running", False))
            except Exception:
                pass

            # Fall back to is_running() method if _running flag doesn't exist
            try:
                return bool(self.receiver_manager.is_running())
            except Exception:
                return False

    def register_client(self) -> None:
        """Increment active WebSocket client count."""
        with self.client_lock:
            self.connected_clients += 1
            logger.debug("WebSocket client connected. Total clients: %d", self.connected_clients)

    def unregister_client(self) -> None:
        """Decrement active WebSocket client count."""
        with self.client_lock:
            self.connected_clients = max(0, self.connected_clients - 1)
            logger.debug("WebSocket client disconnected. Total clients: %d", self.connected_clients)

    def start_monitoring(self, emit_callback: Optional[Any] = None) -> None:
        """Start the system resource monitoring thread."""
        with self._monitor_lock:
            if self._monitor_running:
                return
            self._monitor_running = True
            self._stop_event.clear()
            self._monitor_thread = threading.Thread(
                target=self._monitoring_loop,
                args=(emit_callback,),
                name="SCTAP-SystemMonitor",
                daemon=True
            )
            self._monitor_thread.start()
            logger.info("System monitoring background thread started")

    def stop_monitoring(self) -> None:
        """Stop the system resource monitoring thread."""
        with self._monitor_lock:
            self._monitor_running = False
            self._stop_event.set()
            if self._monitor_thread:
                self._monitor_thread.join(timeout=2.0)
                self._monitor_thread = None
            logger.info("System monitoring background thread stopped")

    def get_metrics(self) -> Dict[str, Any]:
        """Return a copy of the current metrics cache."""
        with self._metrics_lock:
            return dict(self.metrics_cache)

    def _monitoring_loop(self, emit_callback: Optional[Any]) -> None:
        """Loop that gathers metrics every 2 seconds and fires the callback."""
        # Initialize throughput tracker
        try:
            self._last_packet_count = self.db.count("packets")
        except Exception:
            self._last_packet_count = 0
        self._last_time = time.time()
        
        while not self._stop_event.is_set():
            try:
                metrics = self._gather_metrics()
                with self._metrics_lock:
                    self.metrics_cache = metrics
                
                if emit_callback:
                    try:
                        emit_callback(metrics)
                    except Exception as ce:
                        logger.error("Failed to execute monitoring emit callback: %s", ce)
            except Exception as e:
                logger.error("Error in system monitoring loop: %s", e)
            
            self._stop_event.wait(timeout=2.0)

    def _gather_metrics(self) -> Dict[str, Any]:
        """Query and compute system metrics for Windows/Linux platforms."""
        cpu = self._get_cpu_usage()
        ram = self._get_ram_usage()
        
        # Database Stats
        db_path = self.cfg.DATABASE_PATH
        db_size = db_path.stat().st_size if db_path.exists() else 0
        db_status = "healthy" if self.db.table_exists("packets") else "initializing"
        
        # Calculate Packets Per Second (PPS)
        now = time.time()
        time_delta = now - self._last_time
        try:
            current_packets = self.db.count("packets")
            packet_delta = max(0, current_packets - self._last_packet_count)
            pps = round(packet_delta / time_delta, 2) if time_delta > 0 else 0.0
            
            self._last_packet_count = current_packets
            self._last_time = now
        except Exception as dbe:
            logger.warning("Failed to query packets count for PPS: %s", dbe)
            pps = 0.0
            db_status = "degraded"
            
        # Socket status checking
        socket_status = "inactive"
        if self.is_receiver_running():
            socket_status = "listening"
        
        # Read connected_clients under lock
        with self.client_lock:
            clients = self.connected_clients
            
        # Overall System Health Assessment
        health = "healthy"
        if db_status == "degraded" or cpu > 90.0 or ram > 95.0:
            health = "degraded"
        elif db_status == "initializing":
            health = "initializing"
            
        return {
            "cpu_usage": round(cpu, 1),
            "memory_usage": round(ram, 1),
            "db_status": db_status,
            "db_size_bytes": db_size,
            "connected_clients": clients,
            "receiver_running": self.is_receiver_running(),
            "socket_status": socket_status,
            "packets_per_second": pps,
            "system_health": health
        }

    def _get_cpu_usage(self) -> float:
        """Platform-agnostic CPU usage retrieval."""
        if platform.system() == "Windows":
            return self._get_cpu_usage_windows()
        else:
            return self._get_cpu_usage_linux()

    def _get_cpu_usage_windows(self) -> float:
        """Fetch Windows CPU load percentage since last check."""
        try:
            idle = FILETIME()
            kernel = FILETIME()
            user = FILETIME()
            
            # kernel32.GetSystemTimes returns 1 on success
            success = ctypes.windll.kernel32.GetSystemTimes(
                ctypes.byref(idle), ctypes.byref(kernel), ctypes.byref(user)
            )
            if not success:
                return 0.0
                
            idle_i = _ft_to_int(idle)
            kernel_i = _ft_to_int(kernel)
            user_i = _ft_to_int(user)
            
            if self._last_idle_time == 0:
                # First run, record and return 0
                self._last_idle_time = idle_i
                self._last_kernel_time = kernel_i
                self._last_user_time = user_i
                return 0.0
                
            idle_diff = idle_i - self._last_idle_time
            kernel_diff = kernel_i - self._last_kernel_time
            user_diff = user_i - self._last_user_time
            
            self._last_idle_time = idle_i
            self._last_kernel_time = kernel_i
            self._last_user_time = user_i
            
            total = kernel_diff + user_diff
            if total == 0:
                return 0.0
                
            # CPU = 1.0 - (idle / total)
            cpu = (1.0 - (idle_diff / total)) * 100.0
            return max(0.0, min(100.0, cpu))
        except Exception as e:
            logger.debug("Windows CPU monitor error: %s", e)
            return 0.0

    def _get_cpu_usage_linux(self) -> float:
        """Fetch Linux CPU usage by parsing /proc/stat."""
        try:
            stat_file = Path("/proc/stat")
            if not stat_file.exists():
                return 0.0
                
            with open(stat_file, "r") as f:
                line = f.readline()
            
            parts = line.split()
            if len(parts) < 5:
                return 0.0
                
            # user, nice, system, idle
            user_t = int(parts[1])
            nice_t = int(parts[2])
            sys_t = int(parts[3])
            idle_t = int(parts[4])
            
            total = user_t + nice_t + sys_t + idle_t
            
            if self._last_idle_time == 0:
                self._last_idle_time = idle_t
                self._last_kernel_time = total
                return 0.0
                
            idle_diff = idle_t - self._last_idle_time
            total_diff = total - self._last_kernel_time
            
            self._last_idle_time = idle_t
            self._last_kernel_time = total
            
            if total_diff == 0:
                return 0.0
                
            cpu = (1.0 - (idle_diff / total_diff)) * 100.0
            return max(0.0, min(100.0, cpu))
        except Exception as e:
            logger.debug("Linux CPU monitor error: %s", e)
            return 0.0

    def _get_ram_usage(self) -> float:
        """Platform-agnostic RAM usage percentage."""
        if platform.system() == "Windows":
            try:
                stat = MEMORYSTATUSEX()
                stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
                ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat))
                return float(stat.dwMemoryLoad)
            except Exception as e:
                logger.debug("Windows memory monitor error: %s", e)
                return 0.0
        else:
            try:
                # Linux memory check via /proc/meminfo
                mem_file = Path("/proc/meminfo")
                if not mem_file.exists():
                    return 0.0
                    
                meminfo = {}
                with open(mem_file, "r") as f:
                    for line in f:
                        parts = line.split(":")
                        if len(parts) == 2:
                            meminfo[parts[0].strip()] = int(parts[1].replace("kB", "").strip())
                            
                total = meminfo.get("MemTotal", 0)
                free = meminfo.get("MemFree", 0)
                buffers = meminfo.get("Buffers", 0)
                cached = meminfo.get("Cached", 0)
                
                if total == 0:
                    return 0.0
                    
                used = total - free - buffers - cached
                return (used / total) * 100.0
            except Exception as e:
                logger.debug("Linux memory monitor error: %s", e)
                return 0.0


# Module level singleton accessor
_dashboard_manager: Optional[DashboardStateManager] = None
_manager_lock = threading.Lock()

def get_dashboard_manager() -> DashboardStateManager:
    """Return the DashboardStateManager singleton."""
    global _dashboard_manager
    with _manager_lock:
        if _dashboard_manager is None:
            _dashboard_manager = DashboardStateManager()
        return _dashboard_manager

def reset_dashboard_manager() -> None:
    """Reset the singleton instance (primarily for tests)."""
    global _dashboard_manager
    with _manager_lock:
        if _dashboard_manager is not None:
            _dashboard_manager.stop_monitoring()
            _dashboard_manager.stop_receiver()
            _dashboard_manager = None