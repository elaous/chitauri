import pytest

from app.rate_limit import limiter


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    """Reset shared Limiter storage before each test."""
    limiter.reset()
    yield
