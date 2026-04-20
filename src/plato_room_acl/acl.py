"""Room access control with role-based permissions."""
from dataclasses import dataclass, field
from enum import Enum, auto

class Permission(Enum):
    READ = auto()
    WRITE = auto()
    DELETE = auto()
    ADMIN = auto()

class Role(Enum):
    GUEST = "guest"
    MEMBER = "member"
    MODERATOR = "moderator"
    OWNER = "owner"

ROLE_PERMISSIONS = {
    Role.GUEST: {Permission.READ},
    Role.MEMBER: {Permission.READ, Permission.WRITE},
    Role.MODERATOR: {Permission.READ, Permission.WRITE, Permission.DELETE},
    Role.OWNER: {Permission.READ, Permission.WRITE, Permission.DELETE, Permission.ADMIN},
}

@dataclass
class AclEntry:
    agent: str
    role: Role = Role.GUEST
    granted_by: str = ""

class RoomAcl:
    def __init__(self, default_role: str = "guest"):
        self._entries: dict[str, AclEntry] = {}
        self.default_role = Role(default_role)

    def grant(self, agent: str, role: str, granted_by: str = "") -> AclEntry:
        entry = AclEntry(agent=agent, role=Role(role), granted_by=granted_by)
        self._entries[agent] = entry
        return entry

    def revoke(self, agent: str):
        self._entries.pop(agent, None)

    def check(self, agent: str, permission: Permission) -> bool:
        entry = self._entries.get(agent)
        role = entry.role if entry else self.default_role
        return permission in ROLE_PERMISSIONS.get(role, set())

    def role_of(self, agent: str) -> str:
        entry = self._entries.get(agent)
        return entry.role.value if entry else self.default_role.value

    def agents_with_role(self, role: str) -> list[str]:
        return [a for a, e in self._entries.items() if e.role.value == role]

    def promote(self, agent: str, new_role: str) -> bool:
        entry = self._entries.get(agent)
        if entry:
            entry.role = Role(new_role)
            return True
        return False

    @property
    def stats(self) -> dict:
        roles = {}
        for e in self._entries.values():
            roles[e.role.value] = roles.get(e.role.value, 0) + 1
        return {"total_entries": len(self._entries), "roles": roles,
                "default_role": self.default_role.value}
