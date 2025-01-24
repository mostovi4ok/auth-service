from datetime import datetime
from typing import Literal

from pydantic import BaseModel


class Cookie(BaseModel):
    key: str
    value: str = ""
    max_age: int | None = None
    expires: datetime | str | int | None = None
    path: str | None = "/"
    domain: str | None = None
    secure: bool = False
    httponly: bool = False
    samesite: Literal["lax", "strict", "none"] | None = "lax"
