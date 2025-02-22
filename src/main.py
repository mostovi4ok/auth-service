from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

from async_fastapi_jwt_auth.exceptions import AuthJWTException
from fastapi import Depends
from fastapi import FastAPI
from fastapi import Request
from fastapi import Response
from fastapi import status
from fastapi.responses import JSONResponse
from fastapi.responses import ORJSONResponse
from redis.asyncio import Redis

from src.api import access_control
from src.api import auth
from src.core.config import JWTConfig
from src.core.config import configs
from src.core.config import jwt_config
from src.core.logger import setup_root_logger
from src.db import redis_db
from src.jwt_auth_helpers import CustomAuthJWT
from src.jwt_auth_helpers import check_permissions
from src.middleware.middleware import setup_middleware
from src.models.errors import ErrorBody
from src.services.custom_error import JWTBannedError
from src.services.custom_error import MisdirectedRequestError
from src.services.custom_error import ResponseError


setup_root_logger()


@CustomAuthJWT.load_config
def get_config() -> JWTConfig:
    return jwt_config


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncGenerator[None, Any]:
    redis_db.redis = Redis(host=configs.redis_host, port=configs.redis_port)
    yield
    await redis_db.redis.close()


tags_metadata = [
    auth.auth_tags_metadata,
    access_control.permissions_tags_metadata,
]

responses: dict[str | int, Any] = {
    status.HTTP_421_MISDIRECTED_REQUEST: {"model": ErrorBody},
}


app = FastAPI(
    title=configs.name_app,
    description="",
    version="1.0.0",
    docs_url="/api/openapi",
    openapi_url="/api/openapi.json",
    redoc_url="/api/redoc",
    openapi_tags=tags_metadata,
    default_response_class=ORJSONResponse,
    responses=responses,
    lifespan=lifespan,
)

setup_middleware(app)


@app.exception_handler(MisdirectedRequestError)
async def misdirected_error_handler(_: Request, exc: MisdirectedRequestError) -> JSONResponse:  # noqa: RUF029
    return JSONResponse(status_code=status.HTTP_421_MISDIRECTED_REQUEST, content=exc.body.model_dump())


@app.exception_handler(AuthJWTException)
async def authjwt_exception_handler(_: Request, exc: AuthJWTException) -> JSONResponse:  # noqa: RUF029
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.message})


@app.exception_handler(ResponseError)
async def response_exception_handler(_: Request, exc: ResponseError) -> JSONResponse:  # noqa: RUF029
    return JSONResponse(status_code=exc.status_code, content=exc.body.model_dump())


@app.exception_handler(JWTBannedError)
async def jwt_banned_exception_handler(_: Request, exc: JWTBannedError) -> Response:  # noqa: RUF029
    return exc.response


app.include_router(auth.router, prefix="/auth")
app.include_router(access_control.router, prefix="/permission", dependencies=[Depends(check_permissions)])
