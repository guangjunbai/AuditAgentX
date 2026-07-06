"""pytest 全局夹具：确保测试前数据库表已建好。"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.database import init_db


@pytest.fixture(scope="session", autouse=True)
def _setup_database():
    init_db()
    yield
