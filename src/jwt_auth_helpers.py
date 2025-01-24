from typing import Annotated

from fastapi import Depends
from fastapi import HTTPException
from fastapi import status

from src.core.config import configs
from src.custom_auth_jwt import CustomAuthJWT
from src.custom_auth_jwt import CustomAuthJWTBearer
from src.custom_auth_jwt import RawToken
from src.services.permission_management_service import PermissionManagementService
from src.services.permission_management_service import get_permission_management_service


auth_dep = CustomAuthJWTBearer()


async def check_permissions(
    jwt: Annotated[CustomAuthJWT, Depends(auth_dep)],
    permission_management_service: Annotated[PermissionManagementService, Depends(get_permission_management_service)],
) -> None:
    await jwt.jwt_required()
    raw_jwt = await jwt.get_raw_jwt()
    assert raw_jwt is not None
    raw_token = RawToken.model_validate(raw_jwt)
    permissions_user = set(raw_token.permissions)
    all_permissions = await permission_management_service.get_all()

    required_permissions = {
        permission.id for permission in all_permissions.permissions if permission.name in configs.names_permission
    }
    if not permissions_user or any(permission not in permissions_user for permission in required_permissions):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Недостаточно прав")
