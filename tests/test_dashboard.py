"""
Unit tests for the Dashboard State and System Monitoring Manager.
"""

import time
from unittest.mock import MagicMock, patch
import pytest

from dashboard.manager import (
    get_dashboard_manager,
    reset_dashboard_manager,
    DashboardStateManager,
)


@pytest.fixture(autouse=True)
def clean_dashboard_manager():
    """Ensure dashboard manager singleton is clean before and after each test."""
    reset_dashboard_manager()
    yield
    reset_dashboard_manager()


def test_singleton_retrieval(config, db):
    """Test that get_dashboard_manager returns the same instance and resets properly."""
    manager1 = get_dashboard_manager()
    manager2 = get_dashboard_manager()
    assert manager1 is manager2

    reset_dashboard_manager()
    manager3 = get_dashboard_manager()
    assert manager3 is not manager1


def test_client_registration():
    """Test WebSocket client connection registering and unregistering counts."""
    manager = get_dashboard_manager()
    assert manager.connected_clients == 0

    manager.register_client()
    assert manager.connected_clients == 1

    manager.register_client()
    assert manager.connected_clients == 2

    manager.unregister_client()
    assert manager.connected_clients == 1

    # Ensure count never drops below zero
    manager.unregister_client()
    manager.unregister_client()
    assert manager.connected_clients == 0


@patch("dashboard.manager.ReceiverManager")
def test_receiver_start_stop(mock_receiver_class, config, db):
    """Test starting and stopping the UDP receiver via dashboard manager."""
    manager = get_dashboard_manager()
    
    mock_instance = MagicMock()
    mock_receiver_class.return_value = mock_instance
    mock_instance.receiver._running = True

    # Start receiver
    success = manager.start_receiver("test-password")
    assert success is True
    assert manager.current_password == "test-password"
    mock_receiver_class.assert_called_once()
    mock_instance.start.assert_called_once()

    # Check is running
    assert manager.is_receiver_running() is True

    # Stop receiver
    success_stop = manager.stop_receiver()
    assert success_stop is True
    mock_instance.stop.assert_called_once()
    assert manager.is_receiver_running() is False


def test_gather_metrics_keys(config, db):
    """Test that _gather_metrics returns all required structure keys and computes health."""
    manager = get_dashboard_manager()
    metrics = manager._gather_metrics()

    assert "cpu_usage" in metrics
    assert "memory_usage" in metrics
    assert "db_status" in metrics
    assert "db_size_bytes" in metrics
    assert "connected_clients" in metrics
    assert "receiver_running" in metrics
    assert "socket_status" in metrics
    assert "packets_per_second" in metrics
    assert "system_health" in metrics


def test_monitoring_loop_calls_callback(config, db):
    """Test that the monitoring background thread loop invokes the emit callback."""
    manager = get_dashboard_manager()
    callback_mock = MagicMock()

    # Start monitoring with a callback
    manager.start_monitoring(emit_callback=callback_mock)
    
    # Wait briefly for the loop to run at least once
    time.sleep(0.5)
    
    # Stop monitoring
    manager.stop_monitoring()
    
    # Assert callback was called at least once
    assert callback_mock.call_count >= 1
