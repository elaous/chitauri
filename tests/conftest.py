import pytest

from app.rate_limit import limiter


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    """The slowapi Limiter is a single module-level instance shared by every
    test in this process (it's created at app.rate_limit import time, same
    as in production). Reset its storage before each test so one test's
    request volume can't trip another's rate limit."""
    limiter.reset()
    yield
