from redis.asyncio import Redis


redis: Redis | None = None


def get_redis() -> Redis:
    assert redis is not None
    return redis
