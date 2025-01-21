from datetime import UTC
from datetime import datetime
from typing import Annotated
from typing import cast
from uuid import UUID

from async_fastapi_jwt_auth.auth_jwt import AuthJWT
from async_fastapi_jwt_auth.auth_jwt import AuthJWTBearer
from fastapi import APIRouter
from fastapi import Depends
from fastapi import HTTPException
from fastapi import status
from fastapi.responses import Response

from src.api.models import AccountModel
from src.api.models import ChangePasswordModel
from src.api.models import LoginModel
from src.api.models import SecureAccountModel
from src.core.config import jwt_config
from src.services.jwt_service import JWTService
from src.services.jwt_service import TokenData
from src.services.jwt_service import get_jwt_service
from src.services.password_service import PasswordService
from src.services.password_service import get_password_service
from src.services.redis_service import Key
from src.services.redis_service import RedisService
from src.services.redis_service import get_service_redis
from src.services.user_service import UserService
from src.services.user_service import get_user_service


router = APIRouter()
auth_dep = AuthJWTBearer()
auth_tags_metadata = {"name": "Авторизация", "description": "Авторизация в API."}


@router.post(
    "/register",
    summary="Регистрация пользователя",
    description="Регистрация пользователя",
    response_description="Пользователь зарегистрирован",
    tags=["Авторизация"],
)
async def register(
    data: AccountModel,
    user_service: Annotated[UserService, Depends(get_user_service)],
) -> SecureAccountModel:
    if not data.login:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Нужен логин")

    if not data.login:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Нужен пароль")

    if await user_service.get_user(data.login):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Логин занят")

    user = await user_service.create_user(data)
    return SecureAccountModel.model_validate(user.__dict__)


@router.post(
    "/login",
    summary="Авторизация пользователя",
    description="Авторизация пользователя",
    response_description="Пользователь авторизован",
    responses={status.HTTP_401_UNAUTHORIZED: {}},
    tags=["Авторизация"],
)
async def login(
    account: LoginModel,
    user_service: Annotated[UserService, Depends(get_user_service)],
    password_service: Annotated[PasswordService, Depends(get_password_service)],
    authorize: Annotated[AuthJWT, Depends(auth_dep)],
) -> None:
    if (user := await user_service.get_user(account.login)) is None or not await password_service.check_password(
        account.password, user.password
    ):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Неверный логин или пароль")

    rights = {"rights": [str(right.id) for right in user.rights]}
    user_id = str(user.id)
    access_token = await authorize.create_access_token(subject=user_id, user_claims=rights)
    refresh_token = await authorize.create_refresh_token(subject=user_id, user_claims=rights)

    await authorize.set_access_cookies(access_token)
    await authorize.set_refresh_cookies(refresh_token)


@router.get(
    "/logout",
    summary="Выход из системы",
    description="Выход из системы",
    response_description="Пользователь вышел из системы",
    tags=["Авторизация"],
)
async def logout(
    redis: Annotated[RedisService, Depends(get_service_redis)],
    authorize: Annotated[AuthJWT, Depends(auth_dep)],
    jwt: Annotated[JWTService, Depends(get_jwt_service)],
) -> None:
    await authorize.jwt_required()
    token_data = await jwt.get_access_token_data(authorize)
    user_id = token_data.user_id

    await jwt.check_banned(token_data)

    await authorize.jwt_refresh_token_required()
    refresh_token = cast(str, authorize._token)
    jti_refresh = await authorize.get_jti(refresh_token)
    raw_refresh = cast(dict[str, str | int | bool], await authorize.get_raw_jwt())

    now = int(datetime.now(UTC).timestamp())
    await redis.set(
        Key("access_banned", user_id, token_data.jti), token_data.token, cast(int, token_data.raw_token["exp"]) - now
    )
    await redis.set(Key("refresh_banned", user_id, jti_refresh), refresh_token, cast(int, raw_refresh["exp"]) - now)

    await authorize.unset_jwt_cookies()


@router.get(
    "/logout_all",
    summary="Выход из системы со всех устройств",
    description="Выход из системы со всех устройств",
    response_description="Пользователь вышел со всех устройств",
    tags=["Авторизация"],
)
async def logout_all(
    redis: Annotated[RedisService, Depends(get_service_redis)],
    authorize: Annotated[AuthJWT, Depends(auth_dep)],
    jwt: Annotated[JWTService, Depends(get_jwt_service)],
) -> None:
    await authorize.jwt_required()
    token_data = await jwt.get_access_token_data(authorize)
    user_id = token_data.user_id

    await jwt.check_banned(token_data)

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
    tags=["Авторизация"],
)
async def change_password(
    data: ChangePasswordModel,
    password_service: Annotated[PasswordService, Depends(get_password_service)],
    user_service: Annotated[UserService, Depends(get_user_service)],
    authorize: Annotated[AuthJWT, Depends(auth_dep)],
    jwt: Annotated[JWTService, Depends(get_jwt_service)],
) -> Response:
    await authorize.jwt_required()
    access_token_data = await jwt.get_access_token_data(authorize)
    user_id = access_token_data.user_id

    await jwt.check_banned(access_token_data)

    if (user := await user_service.get_user_by_id(user_id)) is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Аккаунт удалён")

    if not await password_service.check_password(data.old_password, user.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Неверный пароль")

    await user_service.change_password(user, data.new_password)
    return Response(status_code=status.HTTP_200_OK)


@router.delete(
    "/delete",
    summary="Удаление аккаунта",
    description="Удаление аккаунта",
    response_description="Аккаунт удалён",
    responses={status.HTTP_204_NO_CONTENT: {}},
    tags=["Авторизация"],
)
async def delete(
    redis: Annotated[RedisService, Depends(get_service_redis)],
    user_service: Annotated[UserService, Depends(get_user_service)],
    authorize: Annotated[AuthJWT, Depends(auth_dep)],
    jwt: Annotated[JWTService, Depends(get_jwt_service)],
) -> Response:
    await authorize.jwt_required()
    token_data = await jwt.get_access_token_data(authorize)
    user_id = token_data.user_id

    await jwt.check_banned(token_data)

    if (user := await user_service.get_user_by_id(user_id)) is not None:
        await user_service.delete_user(user)

    now = int(datetime.now(UTC).timestamp())
    await redis.set(Key("access_banned", "all", user_id), now, jwt_config.authjwt_access_token_expires)
    await redis.set(Key("refresh_banned", "all", user_id), now, jwt_config.authjwt_refresh_token_expires)

    await authorize.unset_jwt_cookies()

    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get(
    "/refresh",
    summary="Обновление токенов",
    description="Обновление токенов",
    response_description="Токены обновлены",
    responses={status.HTTP_401_UNAUTHORIZED: {}},
    tags=["Авторизация"],
)
async def refresh(
    authorize: Annotated[AuthJWT, Depends(auth_dep)],
    jwt: Annotated[JWTService, Depends(get_jwt_service)],
) -> None:
    await authorize.jwt_refresh_token_required()
    refresh_token = cast(str, authorize._token)
    jti = await authorize.get_jti(refresh_token)
    raw_refresh = cast(dict[str, str | int | bool], await authorize.get_raw_jwt())
    iat = cast(int, raw_refresh["iat"])

    user_id = cast(UUID, raw_refresh["sub"])
    rights = cast(str, raw_refresh["rights"])

    await jwt.check_banned(TokenData(user_id=user_id, name_token="refresh", token=refresh_token, jti=jti, iat=iat))  # noqa: S106

    new_access_token = await authorize.create_access_token(subject=str(user_id), user_claims={"rights": rights})

    await authorize.set_access_cookies(new_access_token)


@router.get(
    "/checkout_access",
    summary="Проверка access токена",
    description="Проверка access токена",
    response_description="Жизнеспособность токена",
    tags=["Авторизация"],
)
async def checkout_access(
    authorize: Annotated[AuthJWT, Depends(auth_dep)],
    jwt: Annotated[JWTService, Depends(get_jwt_service)],
) -> None:
    await authorize.jwt_required()
    token_data = await jwt.get_access_token_data(authorize)

    await jwt.check_banned(token_data)
