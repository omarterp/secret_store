import pytest

@pytest.fixture(scope="function")
def reset_secret_store_instance():
    """Fixture to reset the SecretStore singleton instance before each test."""
    from cos import SecretStore
    SecretStore._SecretStore__instance = None
    yield
    SecretStore._SecretStore__instance = None