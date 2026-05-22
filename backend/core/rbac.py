"""
AML Monitoring System — Role-Based Access Control (RBAC)
Fine-grained permission model for Swiss/German banking compliance.
"""
from __future__ import annotations

from enum import Enum
from functools import wraps
from typing import List, Set

from fastapi import Depends, HTTPException, status

from backend.core.auth import get_current_user
from backend.models.account import UserInDB


class Role(str, Enum):
    """System roles aligned with banking department structure."""
    COMPLIANCE_OFFICER = "compliance_officer"   # Full access + GDPR
    AML_ANALYST = "aml_analyst"                 # Read alerts, update FP
    RISK_MANAGER = "risk_manager"               # Read reports, export
    AUDITOR = "auditor"                         # Read-only audit logs
    DATA_ADMIN = "data_admin"                   # GDPR delete workflows
    READONLY = "readonly"                       # Dashboard data only
    SYSTEM = "system"                           # Internal service account


class Permission(str, Enum):
    """Granular permissions mapped to API operations."""
    # Transaction permissions
    TRANSACTIONS_READ = "transactions:read"
    TRANSACTIONS_SCORE = "transactions:score"
    TRANSACTIONS_EXPORT = "transactions:export"

    # Alert permissions
    ALERTS_READ = "alerts:read"
    ALERTS_WRITE = "alerts:write"
    ALERTS_RESOLVE = "alerts:resolve"
    ALERTS_FALSE_POSITIVE = "alerts:false_positive"
    ALERTS_EXPORT = "alerts:export"

    # Account permissions
    ACCOUNTS_READ = "accounts:read"
    ACCOUNTS_PII_READ = "accounts:pii_read"    # Unmasked PII access
    ACCOUNTS_WRITE = "accounts:write"

    # Report permissions
    REPORTS_READ = "reports:read"
    REPORTS_GENERATE = "reports:generate"
    REPORTS_SAR = "reports:sar"                # SAR filing access

    # Admin permissions
    ADMIN_USERS = "admin:users"
    ADMIN_MODELS = "admin:models"
    ADMIN_CONFIG = "admin:config"

    # GDPR permissions
    GDPR_DELETE = "gdpr:delete"
    GDPR_EXPORT = "gdpr:export"
    GDPR_AUDIT = "gdpr:audit"

    # Audit permissions
    AUDIT_READ = "audit:read"
    AUDIT_EXPORT = "audit:export"


# ── Role → Permission Mapping ────────────────────────────────────────────────
ROLE_PERMISSIONS: dict[Role, Set[Permission]] = {
    Role.COMPLIANCE_OFFICER: {
        Permission.TRANSACTIONS_READ, Permission.TRANSACTIONS_SCORE,
        Permission.TRANSACTIONS_EXPORT,
        Permission.ALERTS_READ, Permission.ALERTS_WRITE, Permission.ALERTS_RESOLVE,
        Permission.ALERTS_FALSE_POSITIVE, Permission.ALERTS_EXPORT,
        Permission.ACCOUNTS_READ, Permission.ACCOUNTS_PII_READ, Permission.ACCOUNTS_WRITE,
        Permission.REPORTS_READ, Permission.REPORTS_GENERATE, Permission.REPORTS_SAR,
        Permission.GDPR_DELETE, Permission.GDPR_EXPORT, Permission.GDPR_AUDIT,
        Permission.AUDIT_READ, Permission.AUDIT_EXPORT,
        Permission.ADMIN_MODELS, Permission.ADMIN_CONFIG,
    },
    Role.AML_ANALYST: {
        Permission.TRANSACTIONS_READ, Permission.TRANSACTIONS_SCORE,
        Permission.ALERTS_READ, Permission.ALERTS_WRITE,
        Permission.ALERTS_FALSE_POSITIVE,
        Permission.ACCOUNTS_READ,
        Permission.REPORTS_READ,
        Permission.AUDIT_READ,
    },
    Role.RISK_MANAGER: {
        Permission.TRANSACTIONS_READ, Permission.TRANSACTIONS_EXPORT,
        Permission.ALERTS_READ, Permission.ALERTS_EXPORT,
        Permission.ACCOUNTS_READ,
        Permission.REPORTS_READ, Permission.REPORTS_GENERATE,
        Permission.AUDIT_READ,
    },
    Role.AUDITOR: {
        Permission.TRANSACTIONS_READ,
        Permission.ALERTS_READ,
        Permission.ACCOUNTS_READ,
        Permission.REPORTS_READ,
        Permission.AUDIT_READ, Permission.AUDIT_EXPORT,
        Permission.GDPR_AUDIT,
    },
    Role.DATA_ADMIN: {
        Permission.GDPR_DELETE, Permission.GDPR_EXPORT, Permission.GDPR_AUDIT,
        Permission.AUDIT_READ,
    },
    Role.READONLY: {
        Permission.TRANSACTIONS_READ,
        Permission.ALERTS_READ,
        Permission.ACCOUNTS_READ,
        Permission.REPORTS_READ,
    },
    Role.SYSTEM: set(Permission),  # All permissions for service accounts
}


def get_user_permissions(roles: List[str]) -> Set[Permission]:
    """Compute the union of permissions for a user's roles."""
    permissions: Set[Permission] = set()
    for role_str in roles:
        try:
            role = Role(role_str)
            permissions |= ROLE_PERMISSIONS.get(role, set())
        except ValueError:
            pass  # Unknown role — no permissions granted
    return permissions


def has_permission(user_roles: List[str], required_permission: Permission) -> bool:
    """Check if a user with the given roles has a specific permission."""
    return required_permission in get_user_permissions(user_roles)


# ── FastAPI Dependency Factories ─────────────────────────────────────────────
def require_permission(permission: Permission):
    """
    FastAPI dependency that enforces a specific permission.

    Usage:
        @router.get("/alerts")
        async def list_alerts(
            _: UserInDB = Depends(require_permission(Permission.ALERTS_READ))
        ):
            ...
    """
    async def _check_permission(
        current_user: UserInDB = Depends(get_current_user),
    ) -> UserInDB:
        if not has_permission(current_user.roles, permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "insufficient_permissions",
                    "required": permission.value,
                    "message_de": f"Fehlende Berechtigung: {permission.value}",
                    "message_en": f"Insufficient permissions: {permission.value}",
                },
            )
        return current_user

    return _check_permission


def require_role(role: Role):
    """FastAPI dependency that enforces a specific role."""
    async def _check_role(
        current_user: UserInDB = Depends(get_current_user),
    ) -> UserInDB:
        if role.value not in current_user.roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "insufficient_role",
                    "required_role": role.value,
                    "message_de": f"Rolle erforderlich: {role.value}",
                    "message_en": f"Role required: {role.value}",
                },
            )
        return current_user

    return _check_role


def require_any_role(*roles: Role):
    """FastAPI dependency that enforces at least one of the given roles."""
    async def _check_roles(
        current_user: UserInDB = Depends(get_current_user),
    ) -> UserInDB:
        user_roles = set(current_user.roles)
        required = {r.value for r in roles}
        if not user_roles.intersection(required):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "insufficient_role",
                    "required_any": list(required),
                    "message_de": "Keine der erforderlichen Rollen vorhanden.",
                    "message_en": "None of the required roles present.",
                },
            )
        return current_user

    return _check_roles
