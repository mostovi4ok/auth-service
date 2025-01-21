from dataclasses import dataclass
from functools import lru_cache
from pickle import HIGHEST_PROTOCOL as PICKLE_HIGHEST_PROTOCOL  # noqa: S403
from pickle import dumps as pickle_dumps  # noqa: S403
from pickle import loads as pickle_loads  # noqa: S403
from typing import Annotated
from typing import Any
from uuid import UUID

import backoff
from fastapi import Depends
from redis.asyncio import Redis
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.typing import ExpiryT

from src.db.redis_db import get_redis


type Plug = object


@dataclass(frozen=True, slots=True)
class Key:
    prefix_general: str
    prefix_local: str | UUID
    key: str | UUID

    def __str__(self) -> str:
        return f"{self.prefix_general}:{self.prefix_local}:{self.key}"


class RedisService:
    def __init__(self, redis: Redis) -> None:
        self.redis = redis

    @backoff.on_exception(backoff.expo, RedisConnectionError, max_tries=10)
    async def get(self, key: Key, default: Plug) -> Any | Plug | None:
        if (data := await self.redis.get(str(key))) is None:
            return None

        result = pickle_loads(data)[0]  # noqa: S301
        return default if result is None else result

    @backoff.on_exception(backoff.expo, RedisConnectionError, max_tries=10)
    async def set(self, key: Key, value: Any, expire: ExpiryT | None = None) -> None:
        await self.redis.set(
            str(key),
            pickle_dumps((value,), protocol=PICKLE_HIGHEST_PROTOCOL),
            expire,
        )

    @backoff.on_exception(backoff.expo, RedisConnectionError, max_tries=10)
    async def pipe_set(self, map: dict[Key, Any], expire: ExpiryT | None = None) -> None:
        pipe = self.redis.pipeline()
        for key, value in map.items():
            await pipe.set(
                str(key),
                pickle_dumps((value,), protocol=PICKLE_HIGHEST_PROTOCOL),
                expire,
            )

        await pipe.execute()


@lru_cache
def get_service_redis(redis: Annotated[Redis, Depends(get_redis)]) -> RedisService:
    return RedisService(redis)
