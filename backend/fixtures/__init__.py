"""
backend/fixtures/__init__.py
"""
from backend.fixtures.loader import get_demo_fixture, simulate_agent_latency, is_demo_mode, set_demo_mode

__all__ = ["get_demo_fixture", "simulate_agent_latency", "is_demo_mode", "set_demo_mode"]
