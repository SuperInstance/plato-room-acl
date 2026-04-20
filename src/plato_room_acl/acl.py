"""Room ACL — role-based access control with inheritance, wildcards, and audit logging."""
import time
from dataclasses import dataclass, field
from typing import Optional
from collections import defaultdict
from enum import Enum

class Permission(Enum):
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    ADMIN = "admin"
    INVITE = "invite"
    KICK = "kick"
    BAN = "ban"
    MANAGE_TILES = "manage_tiles"
    MANAGE_ROOM = "manage_room"
    EXPORT = "export"
    AUDIT = "audit"

class Role(Enum):
    OWNER = "owner"
    ADMIN = "admin"
    MODERATOR = "moderator"
    MEMBER = "member"
    VIEWER = "viewer"
    GUEST = "guest"
    BANNED = "banned"

# Role hierarchy: higher role inherits all permissions from lower roles
ROLE_HIERARCHY = {
    Role.OWNER: 6, Role.ADMIN: 5, Role.MODERATOR: 4,
    Role.MEMBER: 3, Role.VIEWER: 2, Role.GUEST: 1, Role.BANNED: 0,
}

ROLE_PERMISSIONS = {
    Role.OWNER: list(Permission),
    Role.ADMIN: [p for p in Permission if p != Permission.ADMIN],
    Role.MODERATOR: [Permission.READ, Permission.WRITE, Permission.DELETE,
                     Permission.MANAGE_TILES, Permission.KICK, Permission.INVITE],
    Role.MEMBER: [Permission.READ, Permission.WRITE, Permission.MANAGE_TILES],
    Role.VIEWER: [Permission.READ, Permission.EXPORT],
    Role.GUEST: [Permission.READ],
    Role.BANNED: [],
}

@dataclass
class ACLEntry:
    agent_id: str
    role: Role
    room: str = ""
    granted_by: str = ""
    granted_at: float = field(default_factory=time.time)
    expires_at: float = 0.0
    permissions: list[Permission] = field(default_factory=list)  # additional permissions beyond role

@dataclass
class AuditEntry:
    agent_id: str
    action: str
    target: str = ""
    permission: str = ""
    allowed: bool = False
    timestamp: float = field(default_factory=time.time)
    reason: str = ""

class RoomACL:
    def __init__(self, audit: bool = True):
        self._entries: dict[str, dict[str, ACLEntry]] = defaultdict(dict)  # room → {agent → entry}
        self._wildcards: dict[str, list[ACLEntry]] = defaultdict(list)  # room → [wildcard entries]
        self._audit_log: list[AuditEntry] = []
        self._audit_enabled = audit

    def grant(self, room: str, agent_id: str, role: Role, granted_by: str = "",
             expires_at: float = 0.0, permissions: list[Permission] = None) -> ACLEntry:
        entry = ACLEntry(agent_id=agent_id, role=role, room=room, granted_by=granted_by,
                        expires_at=expires_at, permissions=permissions or [])
        self._entries[room][agent_id] = entry
        self._audit("grant", agent_id, room, role.value, True)
        return entry

    def revoke(self, room: str, agent_id: str) -> bool:
        entry = self._entries[room].pop(agent_id, None)
        if entry:
            self._audit("revoke", agent_id, room, entry.role.value, True)
            return True
        return False

    def grant_wildcard(self, room: str, pattern: str, role: Role, granted_by: str = ""):
        entry = ACLEntry(agent_id=pattern, role=role, room=room, granted_by=granted_by)
        self._wildcards[room].append(entry)

    def check(self, room: str, agent_id: str, permission: Permission) -> bool:
        # Check direct entry
        entry = self._entries[room].get(agent_id)
        allowed = False
        reason = ""
        if entry:
            if entry.expires_at > 0 and entry.expires_at < time.time():
                reason = "expired"
            elif entry.role == Role.BANNED:
                reason = "banned"
            else:
                # Check role permissions + additional permissions
                role_perms = set(ROLE_PERMISSIONS.get(entry.role, []))
                extra_perms = set(entry.permissions)
                allowed = permission in role_perms or permission in extra_perms
                if not allowed:
                    # Check role hierarchy
                    entry_level = ROLE_HIERARCHY.get(entry.role, 0)
                    for role, level in ROLE_HIERARCHY.items():
                        if level <= entry_level and permission in ROLE_PERMISSIONS.get(role, []):
                            allowed = True
                            break
                reason = f"role={entry.role.value}" if allowed else f"role={entry.role.value} insufficient"
        # Check wildcards
        if not allowed:
            for wc in self._wildcards.get(room, []):
                if self._match_wildcard(wc.agent_id, agent_id):
                    if permission in ROLE_PERMISSIONS.get(wc.role, []):
                        allowed = True
                        reason = f"wildcard={wc.agent_id}"
                        break
        # Default: check if any entry exists
        if not entry and not any(self._match_wildcard(w.agent_id, agent_id) for wc in self._wildcards.get(room, [])):
            allowed = False
            reason = "no entry"
        self._audit("check", agent_id, room, permission.value, allowed, reason)
        return allowed

    def get_role(self, room: str, agent_id: str) -> Optional[Role]:
        entry = self._entries[room].get(agent_id)
        return entry.role if entry else None

    def members(self, room: str, role: Role = None) -> list[ACLEntry]:
        entries = list(self._entries[room].values())
        if role:
            entries = [e for e in entries if e.role == role]
        return entries

    def purge_expired(self) -> int:
        now = time.time()
        purged = 0
        for room in self._entries:
            expired = [aid for aid, e in self._entries[room].items()
                      if e.expires_at > 0 and e.expires_at < now]
            for aid in expired:
                self._entries[room].pop(aid, None)
                purged += 1
        return purged

    def audit_log(self, limit: int = 50) -> list[AuditEntry]:
        return self._audit_log[-limit:]

    def _match_wildcard(self, pattern: str, agent_id: str) -> bool:
        if pattern == "*":
            return True
        if pattern.endswith("*"):
            return agent_id.startswith(pattern[:-1])
        return pattern == agent_id

    def _audit(self, action: str, agent_id: str, target: str, permission: str,
               allowed: bool, reason: str = ""):
        if not self._audit_enabled:
            return
        self._audit_log.append(AuditEntry(
            agent_id=agent_id, action=action, target=target,
            permission=permission, allowed=allowed, reason=reason))
        if len(self._audit_log) > 10000:
            self._audit_log = self._audit_log[-10000:]

    @property
    def stats(self) -> dict:
        rooms = len(self._entries)
        entries = sum(len(e) for e in self._entries.values())
        wildcards = sum(len(w) for w in self._wildcards.values())
        return {"rooms": rooms, "entries": entries, "wildcards": wildcards,
                "audit_entries": len(self._audit_log)}
