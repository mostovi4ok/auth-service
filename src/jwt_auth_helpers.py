from datetime import datetime
from typing import Annotated
from typing import Literal
from typing import cast
from uuid import UUID

from async_fastapi_jwt_auth.auth_jwt import AuthJWT
from async_fastapi_jwt_auth.auth_jwt import AuthJWTBearer
from fastapi import Depends
from fastapi import HTTPException
from fastapi import Request
from fastapi import Response
from fastapi import status
from pydantic import BaseModel

from src.core.config import configs
from src.services.permission_management_service import PermissionManagementService
from src.services.permission_management_service import get_permission_management_service


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


class CustomAuthJWT(AuthJWT):
    async def set_cookies(self, cookie: Cookie, response: Response | None = None) -> None:
        response = response or self._response  # pyright: ignore[reportUnknownVariableType, reportUnknownMemberType, reportAttributeAccessIssue]
        response.set_cookie(**cookie.model_dump())  # pyright: ignore[reportUnknownMemberType]


class CustomAuthJWTBearer(AuthJWTBearer):
    def __call__(self, req: Request = None, res: Response = None) -> CustomAuthJWT:  # pyright: ignore[reportArgumentType]
        return CustomAuthJWT(req, res)


auth_dep = CustomAuthJWTBearer()


async def check_permissions(
    jwt: Annotated[CustomAuthJWT, Depends(auth_dep)],
    permission_management_service: Annotated[PermissionManagementService, Depends(get_permission_management_service)],
) -> None:
    await jwt.jwt_required()
    access = await jwt.get_raw_jwt() or {}
    permissions_user = set(map(UUID, cast(list[str], access.get("permissions", []))))
    all_permissions = await permission_management_service.get_all()

    required_permissions = {
        permission.id for permission in all_permissions.permissions if permission.name in configs.names_permission
    }
    if not permissions_user or any(permission not in permissions_user for permission in required_permissions):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Недостаточно прав")
