import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from main import app
from app.core.database import Base, get_db
from app.core.config import settings

# 1. Connect to jwt_learn_test
TEST_DATABASE_URL = settings.database_url.rsplit("/", 1)[0] + "/jwt_learn_test"
test_engine = create_engine(TEST_DATABASE_URL)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

# 2. Create tables directly from SQLAlchemy models (no Alembic needed)
Base.metadata.create_all(bind=test_engine)

# 3. Override get_db to use test database
def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db

# 4. Clean tables before every test run so each test is fresh
@pytest.fixture(autouse=True)
def clean_tables():
    with test_engine.connect() as conn:
        conn.execute(text("TRUNCATE TABLE user_auth, revoked_tokens RESTART IDENTITY CASCADE;"))
        conn.commit()
    yield

# 5. Provide client fixture to test functions
@pytest.fixture
def client():
    return TestClient(app)