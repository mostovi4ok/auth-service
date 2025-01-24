from dataclasses import dataclass
from uuid import UUID

from pydantic import BaseModel


class RawToken(BaseModel):
    sub: UUID
    iat: int
    jti: UUID
    exp: int
    type: str
    permissions: list[UUID]


@dataclass(slots=True, frozen=True)
class TokenData:
    user_id: UUID
    type: str
    token: str
    jti: str
    iat: int
    exp: int
