from uuid import UUID

from pydantic import BaseModel
from pydantic import Field


class CreatePermissionModel(BaseModel):
    name: str = Field(description="Название права", title="Название")
    description: str | None = Field(default=None, description="Описание права", title="Описание")


class SearchPermissionModel(BaseModel):
    id: UUID | None = Field(default=None, description="Идентификатор права", title="Идентификатор")
    name: str | None = Field(default=None, description="Название права", title="Название")


class ChangePermissionModel(BaseModel):
    name: str | None = Field(default=None, description="Новое название права", title="Новое название")
    description: str | None = Field(default=None, description="Новое описание права", title="Новое описание")


class PermissionModel(CreatePermissionModel):
    id: UUID = Field(description="Идентификатор права", title="Идентификатор")


class PermissionsModel(BaseModel):
    permissions: list[PermissionModel] = Field(description="Список прав", title="Список прав")


class UserModel(BaseModel):
    id: UUID | None = Field(default=None, description="Идентификатор юзера", title="Идентификатор")
    login: str | None = Field(default=None, description="Логин юзера", title="Логин")


class ResponseUserModel(BaseModel):
    id: UUID = Field(description="Идентификатор юзера", title="Идентификатор")
    login: str = Field(description="Логин юзера", title="Логин")
    permissions: list[PermissionModel] = Field(description="Права юзера", title="Права")
