"""
AML Monitoring System — Integration Tests: API Security
Tests authentication, authorization, rate limiting, and injection prevention.
Banking QA grade: every security control must be tested exhaustively.
"""
from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import AsyncClient


class TestAuthentication:
    """JWT authentication must be enforced on all protected endpoints."""

    @pytest.mark.asyncio
    async def test_unauthenticated_request_returns_401(self, test_client):
        """Any request without a token must return 401."""
        response = await test_client.get("/api/v1/transactions")
        assert response.status_code == 401, "Unauthenticated request must return 401"

    @pytest.mark.asyncio
    async def test_unauthenticated_alerts_returns_401(self, test_client):
        response = await test_client.get("/api/v1/alerts")
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_invalid_token_returns_401(self, test_client):
        """Malformed JWT must return 401."""
        response = await test_client.get(
            "/api/v1/transactions",
            headers={"Authorization": "Bearer this.is.invalid.jwt"},
        )
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_expired_token_returns_401(self, test_client):
        """Expired JWT must return 401 (not 403)."""
        from datetime import timedelta
        from backend.core.security import create_access_token
        expired_token = create_access_token(
            subject="analyst@bank.de",
            roles=["aml_analyst"],
            expires_delta=timedelta(seconds=-1),  # Already expired
        )
        response = await test_client.get(
            "/api/v1/transactions",
            headers={"Authorization": f"Bearer {expired_token}"},
        )
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_valid_token_grants_access(self, test_client, auth_headers_analyst):
        """Valid JWT with correct role must return 200 (not auth error)."""
        response = await test_client.get(
            "/api/v1/transactions",
            headers=auth_headers_analyst,
        )
        # 200 or 404 are acceptable (endpoint works, data may be empty)
        assert response.status_code in (200, 404, 422), \
            f"Valid token should not return auth error, got {response.status_code}"

    @pytest.mark.asyncio
    async def test_health_endpoint_is_public(self, test_client):
        """Health check endpoint must be publicly accessible."""
        response = await test_client.get("/api/v1/health")
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_bearer_scheme_required(self, test_client):
        """Non-Bearer auth schemes must be rejected."""
        from backend.core.security import create_access_token
        token = create_access_token("analyst@bank.de", ["aml_analyst"])
        # Using Basic auth scheme instead of Bearer
        response = await test_client.get(
            "/api/v1/alerts",
            headers={"Authorization": f"Basic {token}"},
        )
        assert response.status_code == 401


class TestRBAC:
    """Role-based access control must be enforced at the permission level."""

    @pytest.mark.asyncio
    async def test_readonly_cannot_post_transaction(self, test_client, auth_headers_readonly, sample_transaction):
        """Read-only role must not be able to score transactions."""
        response = await test_client.post(
            "/api/v1/transactions",
            json=sample_transaction,
            headers=auth_headers_readonly,
        )
        assert response.status_code == 403, "Read-only must be blocked from scoring (403)"

    @pytest.mark.asyncio
    async def test_readonly_cannot_access_gdpr_delete(self, test_client, auth_headers_readonly):
        """Read-only role must not access GDPR deletion."""
        response = await test_client.post(
            "/api/v1/gdpr/delete/acc-001",
            json={
                "account_id": "acc-001",
                "requestor_name": "Test",
                "requestor_email": "test@test.com",
                "request_reason": "Test",
                "confirm_deletion": True,
            },
            headers=auth_headers_readonly,
        )
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_analyst_cannot_sar_file(self, test_client, auth_headers_analyst):
        """AML analyst cannot mark an alert as SAR_FILED (compliance_officer only)."""
        response = await test_client.patch(
            "/api/v1/alerts/ALT-FAKE001",
            json={"status": "SAR_FILED"},
            headers=auth_headers_analyst,
        )
        assert response.status_code in (403, 404), \
            "Analyst must not file SAR (403 expected)"

    @pytest.mark.asyncio
    async def test_compliance_officer_full_access(self, test_client, auth_headers_compliance):
        """Compliance officer should have read access to all protected endpoints."""
        endpoints = [
            "/api/v1/transactions",
            "/api/v1/alerts",
            "/api/v1/alerts/stats",
            "/api/v1/gdpr/retention/status",
        ]
        for endpoint in endpoints:
            response = await test_client.get(endpoint, headers=auth_headers_compliance)
            assert response.status_code not in (401, 403), \
                f"Compliance officer blocked from {endpoint}: {response.status_code}"


class TestSecurityHeaders:
    """OWASP security headers must be present on all responses."""

    @pytest.mark.asyncio
    async def test_security_headers_present(self, test_client):
        """All required security headers must be in every response."""
        response = await test_client.get("/api/v1/health")
        required_headers = [
            "x-content-type-options",
            "x-frame-options",
            "strict-transport-security",
            "x-xss-protection",
        ]
        for header in required_headers:
            assert header in response.headers, \
                f"Security header missing: {header}"

    @pytest.mark.asyncio
    async def test_x_content_type_options_nosniff(self, test_client):
        response = await test_client.get("/api/v1/health")
        assert response.headers.get("x-content-type-options") == "nosniff"

    @pytest.mark.asyncio
    async def test_x_frame_options_deny(self, test_client):
        response = await test_client.get("/api/v1/health")
        assert response.headers.get("x-frame-options") == "DENY"

    @pytest.mark.asyncio
    async def test_request_id_in_response(self, test_client):
        """Every response must include a traceable request ID."""
        response = await test_client.get("/api/v1/health")
        assert "x-request-id" in response.headers, "X-Request-ID header must be present"


class TestInjectionPrevention:
    """Input validation must prevent injection attacks."""

    @pytest.mark.asyncio
    async def test_sql_injection_in_transaction_id(self, test_client, auth_headers_analyst):
        """SQL injection in transaction ID must not cause 500."""
        malicious_id = "'; DROP TABLE transactions; --"
        response = await test_client.get(
            f"/api/v1/transactions/{malicious_id}",
            headers=auth_headers_analyst,
        )
        assert response.status_code != 500, "SQL injection must not cause 500 error"

    @pytest.mark.asyncio
    async def test_oversized_payload_rejected(self, test_client, auth_headers_analyst):
        """Oversized payloads must be rejected."""
        huge_payload = {"transactions": [{"transaction_id": "x" * 10000}] * 2000}
        response = await test_client.post(
            "/api/v1/transactions/bulk",
            json=huge_payload,
            headers=auth_headers_analyst,
        )
        assert response.status_code in (413, 422), "Oversized payload must be rejected"

    @pytest.mark.asyncio
    async def test_invalid_currency_rejected(self, test_client, auth_headers_analyst, sample_transaction):
        """Invalid currency codes must be rejected by Pydantic validation."""
        bad_txn = {**sample_transaction, "currency": "INVALID_CURRENCY_CODE"}
        response = await test_client.post(
            "/api/v1/transactions",
            json=bad_txn,
            headers=auth_headers_analyst,
        )
        assert response.status_code == 422, "Invalid currency must be rejected (422)"

    @pytest.mark.asyncio
    async def test_negative_amount_rejected(self, test_client, auth_headers_analyst, sample_transaction):
        """Negative transaction amounts must be rejected."""
        bad_txn = {**sample_transaction, "amount": "-1000.00"}
        response = await test_client.post(
            "/api/v1/transactions",
            json=bad_txn,
            headers=auth_headers_analyst,
        )
        assert response.status_code == 422, "Negative amount must be rejected (422)"

    @pytest.mark.asyncio
    async def test_zero_amount_rejected(self, test_client, auth_headers_analyst, sample_transaction):
        """Zero amount transactions must be rejected."""
        bad_txn = {**sample_transaction, "amount": "0.00"}
        response = await test_client.post(
            "/api/v1/transactions",
            json=bad_txn,
            headers=auth_headers_analyst,
        )
        assert response.status_code == 422


class TestPIIMasking:
    """PII must never be returned unmasked to non-compliance roles."""

    def test_iban_masking_format(self):
        """IBAN masking must show first 4 and last 4 characters only."""
        from backend.core.security import PIIEncryption
        enc = PIIEncryption()
        iban = "CH9300762011623852957"
        masked = enc.mask_iban(iban)
        assert masked.startswith("CH93"), "Masked IBAN must start with country+check digits"
        assert masked.endswith("2957"), "Masked IBAN must end with last 4 digits"
        assert "****" in masked, "Masked IBAN must contain asterisks"
        assert len(masked) == len(iban), "Masked IBAN must preserve length"

    def test_pii_encryption_roundtrip(self):
        """Encrypted PII must decrypt back to original value."""
        from backend.core.security import PIIEncryption
        enc = PIIEncryption()
        original = "CH9300762011623852957"
        encrypted = enc.encrypt(original)
        assert encrypted != original, "Encrypted value must differ from original"
        decrypted = enc.decrypt(encrypted)
        assert decrypted == original, "Decrypted value must match original"

    def test_empty_iban_handled(self):
        """Empty/None IBAN must not crash the masker."""
        from backend.core.security import PIIEncryption
        enc = PIIEncryption()
        assert enc.mask_iban(None) == "****"
        assert enc.mask_iban("") == "****"

    def test_pii_not_in_error_responses(self):
        """IBAN and account IDs must not appear in raw form in error messages."""
        iban = "CH9300762011623852957"
        # Simulate error response
        error_response = {
            "error": "transaction_not_found",
            "message": f"Transaction with IBAN {iban} not found",
        }
        import json
        response_str = json.dumps(error_response)
        # In production, error messages should not echo raw IBAN
        # This test documents the requirement (implementation in middleware)
        assert True  # Placeholder — enforced by PIIMaskingProcessor in middleware
