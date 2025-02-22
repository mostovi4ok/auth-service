from contextlib import suppress
from datetime import UTC
from datetime import datetime
from typing import Annotated

from fastapi import Depends
from sqlalchemy import and_
from sqlalchemy import or_
from sqlalchemy import select
from sqlalchemy import update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.exc import NoResultFound
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from src.api.models.access_control import ChangePermissionModel
from src.api.models.access_control import CreatePermissionModel
from src.api.models.access_control import PermissionModel
from src.api.models.access_control import PermissionsModel
from src.api.models.access_control import ResponseUserModel
from src.api.models.access_control import SearchPermissionModel
from src.api.models.access_control import UserModel
from src.core.config import jwt_config
from src.db.postgres_db import get_session
from src.models.alchemy_model import PermissionOrm
from src.models.alchemy_model import UserOrm
from src.services.custom_error import MisdirectedRequestError
from src.services.redis_service import Key
from src.services.redis_service import RedisService
from src.services.redis_service import get_service_redis


NOT_ENOUGH_INFO = "Недостаточно информации"


class PermissionManagementService:
    def __init__(self, redis: RedisService, session: AsyncSession) -> None:
        self.redis = redis
        self.session = session

    async def create(self, new_right: CreatePermissionModel) -> PermissionModel:
        stmt = select(PermissionOrm).where(PermissionOrm.name == new_right.name)
        if (await self.session.scalars(stmt)).first() is not None:
            raise MisdirectedRequestError(f"Право с названием '{new_right.name}' уже существует")

        right = PermissionOrm(**new_right.model_dump())
        self.session.add(right)
        await self.session.commit()
        await self.session.refresh(right)
        return PermissionModel(id=right.id, name=right.name, description=right.description)

    async def delete(self, right: SearchPermissionModel) -> str:
        if not right.model_dump(exclude_none=True):
            raise MisdirectedRequestError(NOT_ENOUGH_INFO)

        stmt_right = select(PermissionOrm).where(or_(PermissionOrm.name == right.name, PermissionOrm.id == right.id))
        try:
            right_ = (await self.session.scalars(stmt_right)).one()
        except NoResultFound:
            raise MisdirectedRequestError(f"Право '{right.name or right.id}' не существует")

        now = int(datetime.now(UTC).timestamp())
        keys_access_to_redis: dict[Key, int] = {}
        keys_refresh_to_redis: dict[Key, int] = {}
        stmt_users_with_right = select(UserOrm).where(UserOrm.permissions.contains(right_))
        for user in (await self.session.scalars(stmt_users_with_right)).all():
            with suppress(ValueError):
                user.permissions.remove(right_)
                keys_access_to_redis[Key("access_banned", "all", user.id)] = now
                keys_refresh_to_redis[Key("refresh_banned", "all", user.id)] = now

        await self.redis.pipe_set(keys_access_to_redis, jwt_config.authjwt_access_token_expires)
        await self.redis.pipe_set(keys_refresh_to_redis, jwt_config.authjwt_refresh_token_expires)
        await self.session.delete(right_)
        await self.session.commit()
        return f"Право '{right.name or right.id}' удалено"

    async def update(self, right_old: SearchPermissionModel, right_new: ChangePermissionModel) -> PermissionModel:
        if not right_old.model_dump(exclude_none=True) or not right_new.model_dump(exclude_none=True):
            raise MisdirectedRequestError(NOT_ENOUGH_INFO)

        stmt = (
            update(PermissionOrm)
            .where(or_(PermissionOrm.name == right_old.name, PermissionOrm.id == right_old.id))
            .values(**right_new.model_dump(exclude_none=True))
            .returning(PermissionOrm)
        )
        try:
            right = (await self.session.scalars(stmt)).one()
        except NoResultFound:
            raise MisdirectedRequestError(f"Право '{right_old.name or right_old.id}' не существует")
        except IntegrityError:
            raise MisdirectedRequestError(f"Право с названием '{right_new.name}' уже существует")

        now = int(datetime.now(UTC).timestamp())
        keys_access_to_redis: dict[Key, int] = {}
        keys_refresh_to_redis: dict[Key, int] = {}
        stmt_users_with_right = select(UserOrm).where(UserOrm.permissions.contains(right))
        for user in (await self.session.scalars(stmt_users_with_right)).all():
            keys_access_to_redis[Key("access_banned", "all", user.id)] = now
            keys_refresh_to_redis[Key("refresh_banned", "all", user.id)] = now

        await self.redis.pipe_set(keys_access_to_redis, jwt_config.authjwt_access_token_expires)
        await self.redis.pipe_set(keys_refresh_to_redis, jwt_config.authjwt_refresh_token_expires)
        await self.session.commit()
        return PermissionModel(id=right.id, name=right.name, description=right.description)

    async def get_all(self) -> PermissionsModel:
        return PermissionsModel(
            permissions=[
                PermissionModel(id=right.id, name=right.name, description=right.description)
                for right in (await self.session.scalars(select(PermissionOrm))).fetchall()
            ]
        )

    async def assign(self, right: SearchPermissionModel, user: UserModel) -> ResponseUserModel:
        if not right.model_dump(exclude_none=True) or not user.model_dump(exclude_none=True):
            raise MisdirectedRequestError(NOT_ENOUGH_INFO)

        stmt_right = select(PermissionOrm).where(or_(PermissionOrm.name == right.name, PermissionOrm.id == right.id))
        try:
            right_ = (await self.session.scalars(stmt_right)).one()
        except NoResultFound:
            raise MisdirectedRequestError(f"Право '{right.name or right.id}' не существует")

        stmt_user = (
            select(UserOrm)
            .options(selectinload(UserOrm.permissions))
            .where(
                and_(
                    or_(UserOrm.id == user.id, UserOrm.login == user.login),
                    UserOrm.is_deleted == False,  # noqa: E712
                )
            )
        )
        try:
            user_ = (await self.session.scalars(stmt_user)).one()
        except NoResultFound:
            raise MisdirectedRequestError(f"Пользователь '{user.id or user.login}' не существует")

        if right_ in user_.permissions:
            raise MisdirectedRequestError(
                f"Пользователь '{user.id or user.login}' уже имеет право '{right.name or right.id}'"
            )

        user_.permissions.append(right_)

        now = int(datetime.now(UTC).timestamp())
        await self.redis.set(Key("access_banned", "all", user_.id), now, jwt_config.authjwt_access_token_expires)
        await self.redis.set(Key("refresh_banned", "all", user_.id), now, jwt_config.authjwt_refresh_token_expires)
        result = ResponseUserModel(
            id=user_.id,
            login=user_.login,
            permissions=[
                PermissionModel(id=right.id, name=right.name, description=right.description)
                for right in user_.permissions
            ],
        )
        await self.session.commit()
        return result

    async def take_away(self, right: SearchPermissionModel, user: UserModel) -> ResponseUserModel:
        if not right.model_dump(exclude_none=True) or not user.model_dump(exclude_none=True):
            raise MisdirectedRequestError(NOT_ENOUGH_INFO)

        stmt_right = select(PermissionOrm).where(or_(PermissionOrm.name == right.name, PermissionOrm.id == right.id))
        try:
            right_ = (await self.session.scalars(stmt_right)).one()
        except NoResultFound:
            raise MisdirectedRequestError(f"Право '{right.name or right.id}' не существует")

        stmt_user = (
            select(UserOrm)
            .options(selectinload(UserOrm.permissions))
            .where(
                and_(
                    or_(UserOrm.id == user.id, UserOrm.login == user.login),
                    UserOrm.is_deleted == False,  # noqa: E712
                )
            )
        )
        try:
            user_ = (await self.session.scalars(stmt_user)).one()
        except NoResultFound:
            raise MisdirectedRequestError(f"Пользователь '{user.id or user.login}' не существует")

        try:
            user_.permissions.remove(right_)
        except ValueError:
            raise MisdirectedRequestError(
                f"Пользователь '{user.id or user.login}' не имеет право '{right.name or right.id}'"
            )

        now = int(datetime.now(UTC).timestamp())
        await self.redis.set(Key("access_banned", "all", user_.id), now, jwt_config.authjwt_access_token_expires)
        await self.redis.set(Key("refresh_banned", "all", user_.id), now, jwt_config.authjwt_refresh_token_expires)

        result = ResponseUserModel(
            id=user_.id,
            login=user_.login,
            permissions=[
                PermissionModel(id=right.id, name=right.name, description=right.description)
                for right in user_.permissions
            ],
        )
        await self.session.commit()
        return result

    async def get_user_permissions(self, user: UserModel) -> PermissionsModel:
        if not user.model_dump(exclude_none=True):
            raise MisdirectedRequestError(NOT_ENOUGH_INFO)

        stmt = (
            select(UserOrm)
            .options(selectinload(UserOrm.permissions))
            .where(
                and_(
                    or_(UserOrm.id == user.id, UserOrm.login == user.login),
                    UserOrm.is_deleted == False,  # noqa: E712
                )
            )
        )
        try:
            user_ = (await self.session.scalars(stmt)).one()
        except NoResultFound:
            raise MisdirectedRequestError(f"Пользователь '{user.id or user.login}' не существует")

        return PermissionsModel(
            permissions=[
                PermissionModel(id=right.id, name=right.name, description=right.description)
                for right in user_.permissions
            ]
        )


def get_permission_management_service(
    redis: Annotated[RedisService, Depends(get_service_redis)], postgres: Annotated[AsyncSession, Depends(get_session)]
) -> PermissionManagementService:
    return PermissionManagementService(redis, postgres)
