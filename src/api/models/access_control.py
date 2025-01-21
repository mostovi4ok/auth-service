from uuid import UUID

from pydantic import BaseModel
from pydantic import Field


class CreateRightModel(BaseModel):
    name: str = Field(description="Название права", title="Название")
    description: str | None = Field(default=None, description="Описание права", title="Описание")


class SearchRightModel(BaseModel):
    id: UUID | None = Field(default=None, description="Идентификатор права", title="Идентификатор")
    name: str | None = Field(default=None, description="Название права", title="Название")


class ChangeRightModel(BaseModel):
    name: str | None = Field(default=None, description="Новое название права", title="Новое название")
    description: str | None = Field(default=None, description="Новое описание права", title="Новое описание")


class RightModel(CreateRightModel):
    id: UUID = Field(description="Идентификатор права", title="Идентификатор")


class RightsModel(BaseModel):
    rights: list[RightModel] = Field(description="Список прав", title="Список прав")


class UserModel(BaseModel):
    id: UUID | None = Field(default=None, description="Идентификатор юзера", title="Идентификатор")
    login: str | None = Field(default=None, description="Логин юзера", title="Логин")


class ResponseUserModel(BaseModel):
    id: UUID = Field(description="Идентификатор юзера", title="Идентификатор")
    login: str = Field(description="Логин юзера", title="Логин")
    rights: list[RightModel] = Field(description="Права юзера", title="Права")
