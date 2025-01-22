from typing import Annotated
from uuid import UUID

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from sqlalchemy.sql import select

from src.api.models.auth import AccountModel
from src.db.postgres_db import get_session
from src.models.alchemy_model import UserOrm
from src.services.password_service import PasswordService
from src.services.password_service import get_password_service


class UserService:
    def __init__(self, session: AsyncSession, password: PasswordService) -> None:
        self.session = session
        self.password = password

    async def get_user(self, login: str, is_deleted: bool = False) -> UserOrm | None:
        stmt = (
            select(UserOrm)
            .options(selectinload(UserOrm.permissions))
            .where(UserOrm.login == login, UserOrm.is_deleted == is_deleted)
        )
        result = await self.session.execute(stmt)
        return result.scalars().first()

    async def get_user_by_id(self, id_: UUID) -> UserOrm | None:
        stmt = (
            select(UserOrm)
            .options(selectinload(UserOrm.permissions))
            .where(UserOrm.id == id_, UserOrm.is_deleted == False)  # noqa: E712
        )
        result = await self.session.execute(stmt)
        return result.scalars().first()

    async def create_user(self, account: AccountModel) -> UserOrm:
        deleted_user = await self.get_user(account.login, True)
        if deleted_user is None:
            user = UserOrm(
                login=account.login,
                password=await self.password.compute_hash(account.password),
            )
            self.session.add(user)
        else:
            user = deleted_user
            user.password = await self.password.compute_hash(account.password)
            user.is_deleted = False

        await self.session.commit()
        await self.session.refresh(user)
        return user

    async def delete_user(self, user: UserOrm) -> None:
        user.is_deleted = True
        user.permissions.clear()
        self.session.add(user)
        await self.session.commit()

    async def change_password(self, user: UserOrm, new_password: str) -> None:
        user.password = await self.password.compute_hash(new_password)
        await self.session.commit()
        await self.session.refresh(user)


def get_user_service(
    postgres: Annotated[AsyncSession, Depends(get_session)],
    password: Annotated[PasswordService, Depends(get_password_service)],
) -> UserService:
    return UserService(postgres, password)
