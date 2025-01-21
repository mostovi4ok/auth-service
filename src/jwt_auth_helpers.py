from typing import Annotated
from typing import cast
from uuid import UUID

from async_fastapi_jwt_auth.auth_jwt import AuthJWT
from async_fastapi_jwt_auth.auth_jwt import AuthJWTBearer
from fastapi import Depends
from fastapi import HTTPException
from fastapi import status

from src.core.config import configs
from src.services.rights_management_service import RightsManagementService
from src.services.rights_management_service import get_rights_management_service


auth_dep = AuthJWTBearer()


async def check_rights(
    jwt: Annotated[AuthJWT, Depends(auth_dep)],
    rights_management_service: Annotated[RightsManagementService, Depends(get_rights_management_service)],
) -> None:
    await jwt.jwt_required()
    access = await jwt.get_raw_jwt() or {}
    rights_user = set(map(UUID, cast(list[str], access.get("rights", []))))
    all_rights = await rights_management_service.get_all()

    required_rights = {right.id for right in all_rights.rights if right.name in configs.names_right}
    if not rights_user or any(right not in rights_user for right in required_rights):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Недостаточно прав")
