from dataclasses import dataclass
from dataclasses import field
from typing import Annotated
from typing import cast
from uuid import UUID

from fastapi import Depends
from fastapi.exceptions import HTTPException
from starlette import status

from src.jwt_auth_helpers import CustomAuthJWT
from src.services.redis_service import Key
from src.services.redis_service import RedisService
from src.services.redis_service import get_service_redis


@dataclass(slots=True, frozen=True)
class TokenData:
    user_id: UUID
    name_token: str
    token: str
    jti: str
    iat: int
    raw_token: dict[str, str | int | bool] = field(default_factory=dict)


class JWTService:
    def __init__(self, redis: RedisService) -> None:
        self.redis = redis

    async def check_banned(self, data: TokenData) -> None:
        user_id = data.user_id
        name_token = data.name_token
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

    async def get_access_token_data(self, jwt: CustomAuthJWT) -> TokenData:
        token = cast(str, jwt._token)
        raw_token = cast(dict[str, str | int | bool], await jwt.get_raw_jwt())
        return TokenData(
            user_id=cast(UUID, await jwt.get_jwt_subject()),
            name_token="access",  # noqa: S106
            token=token,
            raw_token=raw_token,
            jti=await jwt.get_jti(token),
            iat=cast(int, raw_token["iat"]),
        )


def get_jwt_service(redis: Annotated[RedisService, Depends(get_service_redis)]) -> JWTService:
    return JWTService(redis)
