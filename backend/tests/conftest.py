import os

os.environ["MINEGUARD_DATABASE_URL"] = "sqlite:///./test_mineguard.db"
os.environ["MINEGUARD_SECRET_KEY"] = "test-secret-key-long-enough-for-testing"
os.environ["MINEGUARD_ENVIRONMENT"] = "test"

import pytest
from fastapi.testclient import TestClient

from app.core.database import Base, engine
from app.main import app


@pytest.fixture(scope="session")
def client():
    Base.metadata.drop_all(bind=engine)
    with TestClient(app) as test_client:
        yield test_client
    Base.metadata.drop_all(bind=engine)
