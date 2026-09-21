import logging

audit_log = logging.getLogger("audit")


async def record_audit(actor_id: str, action: str) -> None:
    audit_log.info("action=%s actor=%s", action, actor_id)
