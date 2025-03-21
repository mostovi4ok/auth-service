import logging
from logging import Logger
from pathlib import Path
from typing import Final

from pydantic import Field
from pydantic_settings import BaseSettings
from pydantic_settings import SettingsConfigDict


BASE_DIRECTORY: Final = Path()


class Configs(BaseSettings):
    model_config = SettingsConfigDict(env_file=BASE_DIRECTORY / ".env", extra="allow")

    name_app: str = Field(alias="PROJECT_NAME")

    fuzzy_excel_host: str = Field(alias="FUZZY_EXCEL_HOST")
    fuzzy_excel_port: str = Field(alias="FUZZY_EXCEL_PORT")

    @property
    def fuzzy_excel_dsn(self) -> str:
        return f"http://{self.fuzzy_excel_host}:{self.fuzzy_excel_port}"

    @property
    def services_depend_user_id(self) -> tuple[str]:
        return (f"{self.fuzzy_excel_dsn}/admin/set_user",)

    pg_name: str = Field(alias="POSTGRES_DB", serialization_alias="DB_NAME")
    pg_user: str = Field(alias="POSTGRES_USER", serialization_alias="DB_USER")
    pg_password: str = Field(alias="POSTGRES_PASSWORD", serialization_alias="DB_PASSWORD")
    pg_host: str = Field(alias="POSTGRES_HOST", serialization_alias="DB_HOST")
    pg_port: int = Field(alias="POSTGRES_PORT", serialization_alias="DB_PORT")

    redis_host: str = Field(alias="REDIS_HOST")
    redis_port: int = Field(alias="REDIS_PORT")

    permission_names: list[str] = Field(alias="PERMISSION_NAMES")

    @property
    def names_permission(self) -> set[str]:
        return set(self.permission_names)

    iters_password: int = Field(alias="ITERS_PASSWORD")
    hash_name_password: str = Field(alias="HASH_NAME_PASSWORD")

    @property
    def postgres_dsn(self) -> str:
        return f"postgresql+psycopg://{self.pg_user}:{self.pg_password}@{self.pg_host}:{self.pg_port}/{self.pg_name}"

    log_level: str = "INFO"
    logger_filename: str = "../logs/app.log"
    logger_maxbytes: int = 15000000
    logger_mod: str = "a"
    logger_backup_count: int = 15

    @property
    def logger(self) -> Logger:
        return logging.getLogger(self.name_app)


configs = Configs()  # pyright: ignore[reportCallIssue]


class JWTConfig(BaseSettings):
    model_config = SettingsConfigDict(env_file=BASE_DIRECTORY / ".env", extra="allow")

    authjwt_secret_key: str = Field(alias="JWT_SECRET_KEY")
    authjwt_access_token_expires: int = Field(alias="JWT_EXPIRES_ACCESS_SECONDS")
    authjwt_refresh_token_expires: int = Field(alias="JWT_EXPIRES_REFRESH_SECONDS")
    authjwt_token_location: set[str] = {"cookies"}
    authjwt_cookie_csrf_protect: bool = False


jwt_config = JWTConfig()  # pyright: ignore[reportCallIssue]
