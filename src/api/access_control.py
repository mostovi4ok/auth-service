from typing import Annotated

from async_fastapi_jwt_auth.auth_jwt import AuthJWTBearer
from fastapi import APIRouter
from fastapi import Body
from fastapi import Depends
from fastapi import status

from src.api.models.access_control import ChangeRightModel
from src.api.models.access_control import CreateRightModel
from src.api.models.access_control import ResponseUserModel
from src.api.models.access_control import RightModel
from src.api.models.access_control import RightsModel
from src.api.models.access_control import SearchRightModel
from src.api.models.access_control import UserModel
from src.services.rights_management_service import RightsManagementService
from src.services.rights_management_service import get_rights_management_service


router = APIRouter(prefix="/rights")
auth_dep = AuthJWTBearer()
rights_tags_metadata = {"name": "Права", "description": "Управление правами."}


@router.post(
    "/create",
    summary="Создание права",
    description="Создание права",
    response_description="Право создано",
    responses={status.HTTP_200_OK: {"model": RightModel}},
    tags=["Права"],
)
async def create(
    right: CreateRightModel,
    rights_management_service: Annotated[RightsManagementService, Depends(get_rights_management_service)],
) -> RightModel:
    return await rights_management_service.create(right)


@router.delete(
    "/delete",
    summary="Удаление права",
    description="Удаление права",
    response_description="Право удалено",
    tags=["Права"],
)
async def delete(
    right: Annotated[
        SearchRightModel, Body(description="Минимум одно поле должно быть заполненно", title="Право для удаления")
    ],
    rights_management_service: Annotated[RightsManagementService, Depends(get_rights_management_service)],
) -> str:
    return await rights_management_service.delete(right)


@router.put(
    "/update",
    summary="Изменение права",
    description="Изменение права",
    response_description="Право изменено",
    responses={status.HTTP_200_OK: {"model": RightModel}},
    tags=["Права"],
)
async def update(
    right_old: Annotated[
        SearchRightModel, Body(description="Минимум одно поле должно быть заполненно", title="Право для замены")
    ],
    right_new: Annotated[
        ChangeRightModel, Body(description="Минимум одно поле должно быть заполненно", title="Новый данные права")
    ],
    rights_management_service: Annotated[RightsManagementService, Depends(get_rights_management_service)],
) -> RightModel:
    return await rights_management_service.update(right_old, right_new)


@router.get(
    "/get_all",
    summary="Просмотр всех прав",
    description="Просмотр всех прав",
    response_description="Список прав",
    responses={status.HTTP_200_OK: {"model": RightsModel}},
    tags=["Права"],
)
async def get_all(
    rights_management_service: Annotated[RightsManagementService, Depends(get_rights_management_service)],
) -> RightsModel:
    return await rights_management_service.get_all()


@router.post(
    "/assign",
    summary="Назначить пользователю право",
    description="Назначить пользователю право. Допускается ввод минимум одного поля для права и пользователя",
    response_description="Пользователь и его права",
    responses={status.HTTP_200_OK: {"model": ResponseUserModel}},
    tags=["Права"],
)
async def assign(
    right: Annotated[SearchRightModel, Body(description="Минимум одно поле должно быть заполненно", title="Право")],
    user: Annotated[UserModel, Body(description="Минимум одно поле должно быть заполненно", title="Юзер")],
    rights_management_service: Annotated[RightsManagementService, Depends(get_rights_management_service)],
) -> ResponseUserModel:
    return await rights_management_service.assign(right, user)


@router.delete(
    "/take_away",
    summary="Отобрать у пользователя право",
    description="Отобрать у пользователя право",
    response_description="Пользователь и его права",
    responses={status.HTTP_200_OK: {"model": ResponseUserModel}},
    tags=["Права"],
)
async def take_away(
    right: Annotated[SearchRightModel, Body(description="Минимум одно поле должно быть заполненно", title="Право")],
    user: Annotated[UserModel, Body(description="Минимум одно поле должно быть заполненно", title="Юзер")],
    rights_management_service: Annotated[RightsManagementService, Depends(get_rights_management_service)],
) -> ResponseUserModel:
    return await rights_management_service.take_away(right, user)


@router.post(
    "/get_user_rights",
    summary="Получить права пользователя",
    description="Минимум один параметр должен быть заполнен.",
    response_description="Права пользователя",
    responses={status.HTTP_200_OK: {"model": RightsModel}},
    tags=["Права"],
)
async def get_user_rights(
    user: Annotated[UserModel, Body(description="Минимум одно поле должно быть заполненно", title="Юзер")],
    rights_management_service: Annotated[RightsManagementService, Depends(get_rights_management_service)],
) -> RightsModel:
    return await rights_management_service.get_user_rights(user)
