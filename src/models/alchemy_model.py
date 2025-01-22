import uuid
from datetime import datetime

from sqlalchemy import UUID
from sqlalchemy import Boolean
from sqlalchemy import Column
from sqlalchemy import DateTime
from sqlalchemy import ForeignKey
from sqlalchemy import Index
from sqlalchemy import Integer
from sqlalchemy import String
from sqlalchemy import Table
from sqlalchemy.ext.asyncio import AsyncAttrs
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import composite
from sqlalchemy.orm import mapped_column
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from src.services.password_service import Password


class Base(AsyncAttrs, DeclarativeBase):
    pass


user_permission = Table(
    "user_permission",
    Base.metadata,
    Column[uuid.UUID]("user_id", ForeignKey("user.id", ondelete="CASCADE"), primary_key=True),
    Column[uuid.UUID]("permission_id", ForeignKey("permission.id", ondelete="CASCADE"), primary_key=True),
)


class UserOrm(Base):
    __tablename__ = "user"
    __table_args__ = (Index("id_deleted", "id", "is_deleted"), Index("login_deleted", "login", "is_deleted"))

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    login: Mapped[str] = mapped_column(String(60), unique=True, nullable=False)
    is_deleted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=func.now())
    modified_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=func.now(), onupdate=func.now())
    password: Mapped[Password] = composite(
        mapped_column(String(60), nullable=False),
        mapped_column(Integer, nullable=False),
        mapped_column(String(255), nullable=False),
        mapped_column(String(255), nullable=False),
    )

    permissions: Mapped[list["PermissionOrm"]] = relationship(
        secondary=user_permission, back_populates="users", lazy="selectin"
    )

    def __repr__(self) -> str:
        return f"User(id={self.id!r}, login={self.login!r})"


class PermissionOrm(Base):
    __tablename__ = "permission"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(60), unique=True, nullable=False, index=True)
    description: Mapped[str] = mapped_column(String(256), nullable=True)
    created_at: Mapped[DateTime] = mapped_column(DateTime(timezone=True), default=func.now())
    modified_at: Mapped[DateTime] = mapped_column(DateTime(timezone=True), default=func.now(), onupdate=func.now())

    users: Mapped[list[UserOrm]] = relationship(
        secondary=user_permission, back_populates="permissions", lazy="selectin"
    )

    def __repr__(self) -> str:
        return f"Permission(id={self.id!r}, name={self.name!r})"
