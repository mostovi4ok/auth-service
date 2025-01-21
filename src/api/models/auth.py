from pydantic import BaseModel
from pydantic.fields import Field


class ChangePasswordModel(BaseModel):
    old_password: str = Field(description="Старый пароль", title="Old Password", min_length=4)
    new_password: str = Field(description="Новый пароль", title="New Password", min_length=4)


class SecureAccountModel(BaseModel):
    login: str = Field(description="Логин пользователя", title="Login")


class AccountModel(SecureAccountModel):
    password: str = Field(description="Пароль пользователя", title="Password", min_length=4)


class LoginModel(BaseModel):
    login: str = Field(description="Логин пользователя", title="Login")
    password: str = Field(description="Пароль пользователя", title="Password")
