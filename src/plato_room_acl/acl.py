"""Room access control — roles, permissions, inheritance, and policy engine."""
import time
import hashlib
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum

class Permission(Enum):
    READ = "read"
    WRITE = "write"
    ADMIN = "admin"
    INVITE = "invite"
    KICK = "kick"
    BAN = "ban"
    SPEAK = "speak"
    MUTE = "mute"

@dataclass
class Role:
    name: str
    permissions: set[str] = field(default_factory=set)
    inherits_from: str = ""
    priority: int = 0  # higher = more powerful

@dataclass
class AclEntry:
    agent: str
    room: str
    role: str = "guest"
    granted_by: str = ""
    granted_at: float = field(default_factory=time.time)
    expires_at: float = 0.0
    revoked: bool = False

class RoomAcl:
    def __init__(self):
        self._roles: dict[str, Role] = {}
        self._entries: dict[str, AclEntry] = {}  # key = agent:room
        self._bans: dict[str, dict[str, float]] = {}  # room -> {agent: expires_at}
        self._defaults = {"*:read": True, "*:speak": True}
        self._setup_default_roles()

    def _setup_default_roles(self):
        self._roles["guest"] = Role("guest", {"read", "speak"}, priority=0)
        self._roles["member"] = Role("member", {"read", "write", "speak"}, "guest", priority=1)
        self._roles["moderator"] = Role("moderator", {"read", "write", "speak", "mute", "kick"}, "member", priority=2)
        self._roles["admin"] = Role("admin", {"read", "write", "speak", "mute", "kick", "invite", "admin"}, "moderator", priority=3)
        self._roles["owner"] = Role("owner", set(p.value for p in Permission), "admin", priority=4)

    def define_role(self, name: str, permissions: list[str], inherits: str = "", priority: int = 0) -> Role:
        role = Role(name=name, permissions=set(permissions), inherits_from=inherits, priority=priority)
        self._roles[name] = role
        return role

    def grant(self, agent: str, room: str, role: str = "member", granted_by: str = "",
              expires_at: float = 0.0) -> AclEntry:
        if role not in self._roles:
            raise ValueError(f"Unknown role: {role}")
        key = f"{agent}:{room}"
        entry = AclEntry(agent=agent, room=room, role=role, granted_by=granted_by,
                        expires_at=expires_at)
        self._entries[key] = entry
        return entry

    def revoke(self, agent: str, room: str) -> bool:
        key = f"{agent}:{room}"
        entry = self._entries.get(key)
        if entry:
            entry.revoked = True
            return True
        return False

    def check(self, agent: str, room: str, permission: str) -> bool:
        key = f"{agent}:{room}"
        entry = self._entries.get(key)
        if not entry or entry.revoked:
            return self._check_default(permission)
        if entry.expires_at > 0 and time.time() > entry.expires_at:
            entry.revoked = True
            return self._check_default(permission)
        # Check ban
        bans = self._bans.get(room, {})
        if agent in bans:
            if bans[agent] == 0 or time.time() < bans[agent]:
                return False
            del bans[agent]
        # Resolve effective permissions via role inheritance
        effective = self._resolve_permissions(entry.role)
        return permission in effective

    def _resolve_permissions(self, role_name: str) -> set[str]:
        permissions = set()
        visited = set()
        current = role_name
        while current and current not in visited:
            visited.add(current)
            role = self._roles.get(current)
            if role:
                permissions |= role.permissions
                current = role.inherits_from
            else:
                break
        return permissions

    def _check_default(self, permission: str) -> bool:
        return self._defaults.get(f"*:{permission}", False)

    def ban(self, agent: str, room: str, duration: float = 0.0) -> bool:
        if room not in self._bans:
            self._bans[room] = {}
        self._bans[room][agent] = time.time() + duration if duration > 0 else 0.0
        return True

    def unban(self, agent: str, room: str) -> bool:
        bans = self._bans.get(room, {})
        return bans.pop(agent, None) is not None

    def agents_in_room(self, room: str) -> list[dict]:
        results = []
        for key, entry in self._entries.items():
            if entry.room == room and not entry.revoked:
                if entry.expires_at > 0 and time.time() > entry.expires_at:
                    continue
                results.append({"agent": entry.agent, "role": entry.role,
                              "granted_by": entry.granted_by, "granted_at": entry.granted_at})
        return results

    def effective_role(self, agent: str, room: str) -> str:
        entry = self._entries.get(f"{agent}:{room}")
        if entry and not entry.revoked:
            return entry.role
        return "guest"

    @property
    def stats(self) -> dict:
        active = sum(1 for e in self._entries.values() if not e.revoked)
        banned = sum(len(b) for b in self._bans.values())
        return {"roles": len(self._roles), "active_grants": active,
                "banned_agents": banned, "rooms_with_bans": len(self._bans)}
