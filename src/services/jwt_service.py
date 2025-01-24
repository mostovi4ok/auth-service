from typing import Annotated
from typing import cast

from fastapi import Depends
from fastapi.exceptions import HTTPException
from starlette import status

from src.custom_auth_jwt import CustomAuthJWT
from src.models.jwt import RawToken
from src.models.jwt import TokenData
from src.services.redis_service import Key
from src.services.redis_service import RedisService
from src.services.redis_service import get_service_redis


class JWTService:
    def __init__(self, redis: RedisService) -> None:
        self.redis = redis

    async def check_banned(self, data: TokenData) -> None:
        user_id = data.user_id
        name_token = data.type
        prefix_general = f"{name_token}_banned"
        plug = object()
        if (
            (banned := await self.redis.get(Key(prefix_general, user_id, data.jti), plug)) is plug
            or banned == data.token
            or (banned_all := await self.redis.get(Key(prefix_general, "all", user_id), plug)) is plug
            or (isinstance(banned_all, int) and banned_all > data.iat)
        ):
            detail = f"{name_token} token banned"
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail)

    async def get_token_data(self, jwt: CustomAuthJWT) -> TokenData:
        token = jwt.token
        raw_jwt = cast(dict[str, str | int | bool], await jwt.get_raw_jwt())
        assert raw_jwt is not None
        raw_token = RawToken.model_validate(raw_jwt)
        return TokenData(
            user_id=raw_token.sub,
            type=raw_token.type,
            token=token,
            jti=str(raw_token.jti),
            iat=raw_token.iat,
            exp=raw_token.exp
        )


def get_jwt_service(redis: Annotated[RedisService, Depends(get_service_redis)]) -> JWTService:
    return JWTService(redis)
