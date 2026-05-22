"""
AML Monitoring System — Security Core
JWT authentication, PII encryption, secrets management via Azure Key Vault.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Union

from cryptography.fernet import Fernet, MultiFernet
from jose import JWTError, jwt
from passlib.context import CryptContext

from backend.config.logging_config import get_logger
from backend.config.settings import get_settings

logger = get_logger(__name__)
settings = get_settings()

# ── Password Hashing ─────────────────────────────────────────────────────────
pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__rounds=settings.BCRYPT_ROUNDS,
)


def hash_password(password: str) -> str:
    """Hash password using bcrypt."""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against bcrypt hash."""
    return pwd_context.verify(plain_password, hashed_password)


# ── JWT Tokens ───────────────────────────────────────────────────────────────
def create_access_token(
    subject: str,
    roles: list[str],
    extra_claims: Optional[Dict[str, Any]] = None,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """Create signed JWT access token."""
    expire = datetime.now(timezone.utc) + (
        expires_delta
        or timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    payload = {
        "sub": subject,
        "roles": roles,
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "jti": secrets.token_urlsafe(16),  # JWT ID for token revocation
        "iss": settings.APP_NAME,
        "aud": "aml-api",
    }
    if extra_claims:
        payload.update(extra_claims)
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def create_refresh_token(subject: str) -> str:
    """Create long-lived refresh token."""
    expire = datetime.now(timezone.utc) + timedelta(
        days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS
    )
    payload = {
        "sub": subject,
        "type": "refresh",
        "exp": expire,
        "jti": secrets.token_urlsafe(32),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def decode_token(token: str) -> Dict[str, Any]:
    """Decode and validate JWT token."""
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
            audience="aml-api",
        )
        return payload
    except JWTError as e:
        logger.warning("JWT decode failed", error=str(e))
        raise


# ── PII Encryption (Fernet AES-128-CBC with HMAC) ───────────────────────────
class PIIEncryption:
    """
    Encrypt/decrypt PII fields using Fernet (AES-128-CBC + HMAC-SHA256).
    Supports key rotation via MultiFernet.
    """

    def __init__(self):
        primary_key = self._load_key(settings.PII_ENCRYPTION_KEY)
        self._fernet = MultiFernet([Fernet(primary_key)])

    def _load_key(self, key_str: str) -> bytes:
        """Derive a valid Fernet key from the configured key string."""
        # Derive a 32-byte key using SHA-256, then base64-encode it
        key_bytes = hashlib.sha256(key_str.encode()).digest()
        return base64.urlsafe_b64encode(key_bytes)

    def encrypt(self, value: str) -> str:
        """Encrypt a PII value. Returns base64-encoded ciphertext."""
        if not value:
            return value
        encrypted = self._fernet.encrypt(value.encode("utf-8"))
        return encrypted.decode("utf-8")

    def decrypt(self, encrypted_value: str) -> str:
        """Decrypt an encrypted PII value."""
        if not encrypted_value:
            return encrypted_value
        try:
            decrypted = self._fernet.decrypt(encrypted_value.encode("utf-8"))
            return decrypted.decode("utf-8")
        except Exception as e:
            logger.error("PII decryption failed", error=str(e))
            raise ValueError("Failed to decrypt PII field") from e

    def mask(self, value: str, visible_chars: int = 4) -> str:
        """Return masked version of PII for display (e.g., IBAN → CH93****5290)."""
        if not value or len(value) <= visible_chars:
            return "****"
        return value[:visible_chars] + "*" * (len(value) - visible_chars)

    def mask_iban(self, iban: str) -> str:
        """Mask IBAN per PSD2/GDPR standards: show country + check digits + last 4."""
        if not iban or len(iban) < 8:
            return "****"
        clean = iban.replace(" ", "")
        return f"{clean[:4]}{'*' * (len(clean) - 8)}{clean[-4:]}"


# ── Audit Log Signature ──────────────────────────────────────────────────────
class AuditSigner:
    """
    Signs audit log entries with HMAC-SHA256 to ensure tamper-evidence.
    Compliant with FINMA and BaFin audit trail requirements.
    """

    def __init__(self):
        self._key = settings.SECRET_KEY.encode()

    def sign(self, entry: Dict[str, Any]) -> str:
        """Generate HMAC signature for an audit entry."""
        import json
        canonical = json.dumps(entry, sort_keys=True, ensure_ascii=True)
        sig = hmac.new(self._key, canonical.encode(), hashlib.sha256)
        return sig.hexdigest()

    def verify(self, entry: Dict[str, Any], signature: str) -> bool:
        """Verify audit entry signature."""
        expected = self.sign(entry)
        return hmac.compare_digest(expected, signature)


# ── API Key Management ───────────────────────────────────────────────────────
def generate_api_key(prefix: str = "aml") -> tuple[str, str]:
    """
    Generate a new API key pair.
    Returns (plain_key, hashed_key). Store only the hash.
    """
    raw = secrets.token_urlsafe(32)
    plain = f"{prefix}_{raw}"
    hashed = hashlib.sha256(plain.encode()).hexdigest()
    return plain, hashed


def verify_api_key(plain_key: str, stored_hash: str) -> bool:
    """Verify API key against stored SHA-256 hash."""
    computed = hashlib.sha256(plain_key.encode()).hexdigest()
    return hmac.compare_digest(computed, stored_hash)


# ── Singletons ───────────────────────────────────────────────────────────────
pii_encryption = PIIEncryption()
audit_signer = AuditSigner()
