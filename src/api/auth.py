from datetime import UTC
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter
from fastapi import Depends
from fastapi import Response
from fastapi import status

from src.api.models import AccountModel
from src.api.models import ChangePasswordModel
from src.api.models import LoginModel
from src.api.models import SecureAccountModel
from src.core.config import configs
from src.core.config import jwt_config
from src.custom_auth_jwt import CustomAuthJWT
from src.custom_auth_jwt import CustomAuthJWTBearer
from src.models.jwt import Payload
from src.services.custom_error import ResponseError
from src.services.jwt_service import JWTService
from src.services.jwt_service import get_jwt_service
from src.services.password_service import PasswordService
from src.services.password_service import get_password_service
from src.services.redis_service import Key
from src.services.redis_service import RedisService
from src.services.redis_service import get_service_redis
from src.services.user_service import UserService
from src.services.user_service import get_user_service


router = APIRouter(tags=["Авторизация"])
auth_dep = CustomAuthJWTBearer()
auth_tags_metadata = {"name": "Авторизация", "description": "Авторизация в API."}


@router.post(
    "/register",
    summary="Регистрация пользователя",
    description="Регистрация пользователя",
    response_description="Пользователь зарегистрирован",
)
async def register(
    data: AccountModel,
    user_service: Annotated[UserService, Depends(get_user_service)],
) -> SecureAccountModel:
    if await user_service.get_user(data.login):
        raise ResponseError(status.HTTP_409_CONFLICT, "Логин занят")

    user = await user_service.create_user(data)
    await user_service.transfer_user_to_other_services(user.id, configs.services_depend_user_id)
    return SecureAccountModel.model_validate(user.__dict__)


@router.post(
    "/login",
    summary="Авторизация пользователя",
    description="Авторизация пользователя",
    response_description="Пользователь авторизован",
)
async def login(
    account: LoginModel,
    user_service: Annotated[UserService, Depends(get_user_service)],
    password_service: Annotated[PasswordService, Depends(get_password_service)],
    authorize: Annotated[CustomAuthJWT, Depends()],
) -> None:
    if (user := await user_service.get_user(account.login)) is None or not await password_service.check_password(
        account.password, user.password
    ):
        raise ResponseError(status.HTTP_401_UNAUTHORIZED, "Неверный логин или пароль")

    permission = {"permissions": [str(permission.id) for permission in user.permissions]}
    user_id = str(user.id)
    access_token = await authorize.create_access_token(subject=user_id, user_claims=permission)
    refresh_token = await authorize.create_refresh_token(subject=user_id, user_claims=permission)

    await authorize.set_access_cookies(access_token, max_age=jwt_config.authjwt_access_token_expires)
    await authorize.set_refresh_cookies(refresh_token, max_age=jwt_config.authjwt_refresh_token_expires)


@router.get(
    "/logout",
    summary="Выход из системы",
    description="Выход из системы",
    response_description="Пользователь вышел из системы",
)
async def logout(
    redis: Annotated[RedisService, Depends(get_service_redis)],
    authorize: Annotated[CustomAuthJWT, Depends(auth_dep)],
    jwt: Annotated[JWTService, Depends(get_jwt_service)],
) -> None:
    await authorize.jwt_required()
    access_payload = await authorize.get_payload()

    if await jwt.check_banned(access_payload):
        await authorize.raise_banned_jwt(access_payload.type)

    await authorize.jwt_refresh_token_required()
    refresh_payload = await authorize.get_payload()

    user_id = access_payload.user_id
    access_jti = access_payload.jti
    refresh_jti = refresh_payload.jti
    now = int(datetime.now(UTC).timestamp())
    await redis.set(Key("access_banned", user_id, access_jti), access_jti, access_payload.exp - now)
    await redis.set(Key("refresh_banned", user_id, refresh_jti), refresh_jti, refresh_payload.exp - now)

    await authorize.unset_jwt_cookies()


@router.get(
    "/logout_all",
    summary="Выход из системы со всех устройств",
    description="Выход из системы со всех устройств",
    response_description="Пользователь вышел со всех устройств",
)
async def logout_all(
    redis: Annotated[RedisService, Depends(get_service_redis)],
    authorize: Annotated[CustomAuthJWT, Depends(auth_dep)],
    jwt: Annotated[JWTService, Depends(get_jwt_service)],
) -> None:
    await authorize.jwt_required()
    payload = await authorize.get_payload()
    user_id = payload.user_id

    if await jwt.check_banned(payload):
        await authorize.raise_banned_jwt(payload.type)

    now = int(datetime.now(UTC).timestamp())
    await redis.set(Key("access_banned", "all", user_id), now, jwt_config.authjwt_access_token_expires)
    await redis.set(Key("refresh_banned", "all", user_id), now, jwt_config.authjwt_refresh_token_expires)

    await authorize.unset_jwt_cookies()


@router.put(
    "/change_password",
    summary="Изменение пароля",
    description="Изменение пароля",
    response_description="Пароль изменён",
    responses={status.HTTP_200_OK: {}, status.HTTP_401_UNAUTHORIZED: {}},
)
async def change_password(
    data: ChangePasswordModel,
    password_service: Annotated[PasswordService, Depends(get_password_service)],
    user_service: Annotated[UserService, Depends(get_user_service)],
    authorize: Annotated[CustomAuthJWT, Depends(auth_dep)],
    jwt: Annotated[JWTService, Depends(get_jwt_service)],
) -> None:
    await authorize.jwt_required()
    payload = await authorize.get_payload()
    user_id = payload.user_id

    if await jwt.check_banned(payload):
        await authorize.raise_banned_jwt(payload.type)

    if (user := await user_service.get_user_by_id(user_id)) is None:
        raise ResponseError(status.HTTP_401_UNAUTHORIZED, "Аккаунт удалён")

    if not await password_service.check_password(data.old_password, user.password):
        raise ResponseError(status.HTTP_401_UNAUTHORIZED, "Неверный пароль")

    await user_service.change_password(user, data.new_password)


@router.delete(
    "/delete",
    summary="Удаление аккаунта",
    description="Удаление аккаунта",
    response_description="Аккаунт удалён",
    responses={status.HTTP_204_NO_CONTENT: {}},
)
async def delete(
    redis: Annotated[RedisService, Depends(get_service_redis)],
    user_service: Annotated[UserService, Depends(get_user_service)],
    authorize: Annotated[CustomAuthJWT, Depends(auth_dep)],
    jwt: Annotated[JWTService, Depends(get_jwt_service)],
    response: Response,
) -> None:
    await authorize.jwt_required()
    payload = await authorize.get_payload()
    user_id = payload.user_id

    if await jwt.check_banned(payload):
        await authorize.raise_banned_jwt(payload.type)

    if (user := await user_service.get_user_by_id(user_id)) is not None:
        await user_service.delete_user(user)

    now = int(datetime.now(UTC).timestamp())
    await redis.set(Key("access_banned", "all", user_id), now, jwt_config.authjwt_access_token_expires)
    await redis.set(Key("refresh_banned", "all", user_id), now, jwt_config.authjwt_refresh_token_expires)

    await authorize.unset_jwt_cookies()

    response.status_code = status.HTTP_204_NO_CONTENT


@router.get(
    "/refresh",
    summary="Обновление токенов",
    description="Обновление токенов",
    response_description="Токены обновлены",
    responses={status.HTTP_401_UNAUTHORIZED: {}},
)
async def refresh(
    authorize: Annotated[CustomAuthJWT, Depends(auth_dep)],
    jwt: Annotated[JWTService, Depends(get_jwt_service)],
) -> None:
    await authorize.jwt_refresh_token_required()

    payload = await authorize.get_payload()
    user_id = payload.user_id

    if await jwt.check_banned(payload):
        await authorize.raise_banned_jwt(payload.type)

    new_access_token = await authorize.create_access_token(
        subject=str(user_id), user_claims={"permissions": list(map(str, payload.permissions))}
    )

    await authorize.set_access_cookies(new_access_token, max_age=jwt_config.authjwt_access_token_expires)


@router.get(
    "/checkout_access",
    summary="Проверка access токена",
    description="Проверка access токена",
    response_description="Жизнеспособность токена",
)
async def checkout_access(
    authorize: Annotated[CustomAuthJWT, Depends(auth_dep)],
    jwt: Annotated[JWTService, Depends(get_jwt_service)],
) -> None:
    await authorize.jwt_required()
    payload = await authorize.get_payload()

    if await jwt.check_banned(payload):
        await authorize.raise_banned_jwt(payload.type)


@router.get(
    "/get_payload",
    summary="Проверить access токен и получить его payload",
    description="Проверить access токен и получить его payload",
    response_description="Payload",
)
async def get_payload(
    authorize: Annotated[CustomAuthJWT, Depends(auth_dep)],
    jwt: Annotated[JWTService, Depends(get_jwt_service)],
) -> Payload:
    await authorize.jwt_required()
    payload = await authorize.get_payload()

    if await jwt.check_banned(payload):
        await authorize.raise_banned_jwt(payload.type)

    return payload
