from typing import Annotated

from fastapi import Depends

from src.models.jwt import Payload
from src.services.redis_service import Key
from src.services.redis_service import RedisService
from src.services.redis_service import get_service_redis


class JWTService:
    def __init__(self, redis: RedisService) -> None:
        self.redis = redis

    async def check_banned(self, data: Payload) -> bool:
        user_id = data.user_id
        prefix_general = f"{data.type}_banned"
        jti = data.jti
        plug = object()
        return bool(
            (banned := await self.redis.get(Key(prefix_general, user_id, jti), plug)) is plug
            or banned == jti
            or (banned_all := await self.redis.get(Key(prefix_general, "all", user_id), plug)) is plug
            or (isinstance(banned_all, int) and banned_all > data.iat)
        )


def get_jwt_service(redis: Annotated[RedisService, Depends(get_service_redis)]) -> JWTService:
    return JWTService(redis)
