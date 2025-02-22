from uuid import UUID

from pydantic import BaseModel
from pydantic import Field


class Payload(BaseModel):
    user_id: UUID = Field(validation_alias="sub")
    iat: int
    jti: UUID
    exp: int
    type: str
    permissions: list[UUID]
