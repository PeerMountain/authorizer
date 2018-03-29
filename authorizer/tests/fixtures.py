import pytest

@pytest.fixture
def sender_pubkey():
    return """-----BEGIN RSA PRIVATE KEY-----
        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
        -----END RSA PRIVATE KEY-----"""
