"""Path setup so `from worker.X import Y` works inside the container.

Inside the worker container, code lives at /app/ (not /app/worker/).
This conftest makes `worker` importable by pointing it at /app/.
"""
import importlib
import os
import sys
import types

# Make the /app directory (or local worker/) importable as "worker"
_app_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if "worker" not in sys.modules:
    mod = types.ModuleType("worker")
    mod.__path__ = [_app_dir]
    mod.__file__ = os.path.join(_app_dir, "__init__.py")
    sys.modules["worker"] = mod
