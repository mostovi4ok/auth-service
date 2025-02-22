from typing import Annotated

from fastapi import APIRouter
from fastapi import Body
from fastapi import Depends

from src.api.models.access_control import ChangePermissionModel
from src.api.models.access_control import CreatePermissionModel
from src.api.models.access_control import PermissionModel
from src.api.models.access_control import PermissionsModel
from src.api.models.access_control import ResponseUserModel
from src.api.models.access_control import SearchPermissionModel
from src.api.models.access_control import UserModel
from src.services.permission_management_service import PermissionManagementService
from src.services.permission_management_service import get_permission_management_service


router = APIRouter()
permissions_tags_metadata = {"name": "Права", "description": "Управление правами."}


@router.post(
    "/create",
    summary="Создание права",
    description="Создание права",
    response_description="Право создано",
    tags=["Права"],
)
async def create(
    permission: CreatePermissionModel,
    permissions_management_service: Annotated[PermissionManagementService, Depends(get_permission_management_service)],
) -> PermissionModel:
    return await permissions_management_service.create(permission)


@router.delete(
    "/delete",
    summary="Удаление права",
    description="Удаление права",
    response_description="Право удалено",
    tags=["Права"],
)
async def delete(
    permission: Annotated[
        SearchPermissionModel, Body(description="Минимум одно поле должно быть заполненно", title="Право для удаления")
    ],
    permissions_management_service: Annotated[PermissionManagementService, Depends(get_permission_management_service)],
) -> str:
    return await permissions_management_service.delete(permission)


@router.put(
    "/update",
    summary="Изменение права",
    description="Изменение права",
    response_description="Право изменено",
    tags=["Права"],
)
async def update(
    permission_old: Annotated[
        SearchPermissionModel, Body(description="Минимум одно поле должно быть заполненно", title="Право для замены")
    ],
    permission_new: Annotated[
        ChangePermissionModel, Body(description="Минимум одно поле должно быть заполненно", title="Новый данные права")
    ],
    permissions_management_service: Annotated[PermissionManagementService, Depends(get_permission_management_service)],
) -> PermissionModel:
    return await permissions_management_service.update(permission_old, permission_new)


@router.get(
    "/get_all",
    summary="Просмотр всех прав",
    description="Просмотр всех прав",
    response_description="Список прав",
    tags=["Права"],
)
async def get_all(
    permissions_management_service: Annotated[PermissionManagementService, Depends(get_permission_management_service)],
) -> PermissionsModel:
    return await permissions_management_service.get_all()


@router.post(
    "/assign",
    summary="Назначить пользователю право",
    description="Назначить пользователю право. Допускается ввод минимум одного поля для права и пользователя",
    response_description="Пользователь и его права",
    tags=["Права"],
)
async def assign(
    permission: Annotated[
        SearchPermissionModel, Body(description="Минимум одно поле должно быть заполненно", title="Право")
    ],
    user: Annotated[UserModel, Body(description="Минимум одно поле должно быть заполненно", title="Юзер")],
    permissions_management_service: Annotated[PermissionManagementService, Depends(get_permission_management_service)],
) -> ResponseUserModel:
    return await permissions_management_service.assign(permission, user)


@router.delete(
    "/take_away",
    summary="Отобрать у пользователя право",
    description="Отобрать у пользователя право",
    response_description="Пользователь и его права",
    tags=["Права"],
)
async def take_away(
    permission: Annotated[
        SearchPermissionModel, Body(description="Минимум одно поле должно быть заполненно", title="Право")
    ],
    user: Annotated[UserModel, Body(description="Минимум одно поле должно быть заполненно", title="Юзер")],
    permissions_management_service: Annotated[PermissionManagementService, Depends(get_permission_management_service)],
) -> ResponseUserModel:
    return await permissions_management_service.take_away(permission, user)


@router.post(
    "/get_user_permissions",
    summary="Получить права пользователя",
    description="Минимум один параметр должен быть заполнен.",
    response_description="Права пользователя",
    tags=["Права"],
)
async def get_user_permissions(
    user: Annotated[UserModel, Body(description="Минимум одно поле должно быть заполненно", title="Юзер")],
    permissions_management_service: Annotated[PermissionManagementService, Depends(get_permission_management_service)],
) -> PermissionsModel:
    return await permissions_management_service.get_user_permissions(user)
