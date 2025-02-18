from datetime import UTC
from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter
from fastapi import Depends
from fastapi import HTTPException
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
from src.models.jwt import RawToken
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
auth_dep = CustomAuthJWTBearer()
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

    if not data.password:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Нужен пароль")

    if await user_service.get_user(data.login):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Логин занят")

    user = await user_service.create_user(data)
    await user_service.transfer_user_to_other_services(user.id, configs.services_depend_user_id)
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
    authorize: Annotated[CustomAuthJWT, Depends()],
) -> None:
    if (user := await user_service.get_user(account.login)) is None or not await password_service.check_password(
        account.password, user.password
    ):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Неверный логин или пароль")

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
    tags=["Авторизация"],
)
async def logout(
    redis: Annotated[RedisService, Depends(get_service_redis)],
    authorize: Annotated[CustomAuthJWT, Depends(auth_dep)],
    jwt: Annotated[JWTService, Depends(get_jwt_service)],
) -> None:
    await authorize.jwt_required()
    access_data = await jwt.get_token_data(authorize)

    await jwt.check_banned(access_data)

    await authorize.jwt_refresh_token_required()
    refresh_data = await jwt.get_token_data(authorize)

    user_id = access_data.user_id
    now = int(datetime.now(UTC).timestamp())
    await redis.set(Key("access_banned", user_id, access_data.jti), access_data.token, access_data.exp - now)
    await redis.set(Key("refresh_banned", user_id, refresh_data.jti), refresh_data.token, refresh_data.exp - now)

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
    authorize: Annotated[CustomAuthJWT, Depends(auth_dep)],
    jwt: Annotated[JWTService, Depends(get_jwt_service)],
) -> None:
    await authorize.jwt_required()
    token_data = await jwt.get_token_data(authorize)
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
    authorize: Annotated[CustomAuthJWT, Depends(auth_dep)],
    jwt: Annotated[JWTService, Depends(get_jwt_service)],
) -> Response:
    await authorize.jwt_required()
    access_token_data = await jwt.get_token_data(authorize)
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
    authorize: Annotated[CustomAuthJWT, Depends(auth_dep)],
    jwt: Annotated[JWTService, Depends(get_jwt_service)],
) -> Response:
    await authorize.jwt_required()
    token_data = await jwt.get_token_data(authorize)
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
    authorize: Annotated[CustomAuthJWT, Depends(auth_dep)],
    jwt: Annotated[JWTService, Depends(get_jwt_service)],
) -> None:
    await authorize.jwt_refresh_token_required()
    refresh_token = authorize.token
    raw_jwt = await authorize.get_raw_jwt()
    assert raw_jwt is not None
    raw_refresh = RawToken.model_validate(raw_jwt)

    user_id = raw_refresh.sub
    permissions = list(map(str, raw_refresh.permissions))

    await jwt.check_banned(
        TokenData(
            user_id=user_id,
            type=raw_refresh.type,
            token=refresh_token,
            jti=str(raw_refresh.jti),
            iat=raw_refresh.iat,
            exp=raw_refresh.exp,
        )
    )

    new_access_token = await authorize.create_access_token(
        subject=str(user_id), user_claims={"permissions": permissions}
    )

    await authorize.set_access_cookies(new_access_token, max_age=jwt_config.authjwt_access_token_expires)


@router.get(
    "/checkout_access",
    summary="Проверка access токена",
    description="Проверка access токена",
    response_description="Жизнеспособность токена",
    tags=["Авторизация"],
)
async def checkout_access(
    authorize: Annotated[CustomAuthJWT, Depends(auth_dep)],
    jwt: Annotated[JWTService, Depends(get_jwt_service)],
) -> None:
    await authorize.jwt_required()
    token_data = await jwt.get_token_data(authorize)

    await jwt.check_banned(token_data)


@router.get(
    "/fetch_user",
    summary="Проверка access токена",
    description="Проверка access токена",
    response_description="Жизнеспособность токена",
    tags=["Авторизация"],
)
async def fetch_user(
    authorize: Annotated[CustomAuthJWT, Depends(auth_dep)],
    jwt: Annotated[JWTService, Depends(get_jwt_service)],
) -> UUID:
    await authorize.jwt_required()
    token_data = await jwt.get_token_data(authorize)

    await jwt.check_banned(token_data)

    return token_data.user_id
