from __future__ import annotations

import logging
from typing import Any, Optional

from django.contrib.auth import get_user_model

from .models import AuditAction, AuditEvent

logger = logging.getLogger(__name__)
User = get_user_model()


def get_client_ip(request) -> Optional[str]:
    if request is None:
        return None
    xff = request.META.get("HTTP_X_FORWARDED_FOR")
    if xff:
        # first IP is the original client in most proxy setups
        return xff.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR")


def audit_log(
    *,
    action: str | AuditAction,
    request=None,
    actor=None,
    target_user=None,
    success: Optional[bool] = None,
    metadata: Optional[dict[str, Any]] = None,
):
    """
    Safe audit logger: never throws.
    """
    try:
        if request is not None and actor is None:
            u = getattr(request, "user", None)
            actor = u if getattr(u, "is_authenticated", False) else None

        ip = get_client_ip(request)
        user_agent = (request.META.get("HTTP_USER_AGENT") or "") if request is not None else ""

        AuditEvent.objects.create(
            actor=actor,
            target_user=target_user,
            action=str(action),
            success=success,
            ip_address=ip,
            user_agent=user_agent[:2000],
            metadata=metadata or {},
        )
    except Exception as e:
        logger.error("Audit log failed for action=%s: %s", action, e)
