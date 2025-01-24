from asyncio import run as asyncio_run

from sqlalchemy import create_engine
from sqlalchemy import or_
from sqlalchemy import select
from sqlalchemy.orm import Session
from typer import Exit
from typer import Typer

from src.core.config import configs
from src.models.alchemy_model import PermissionOrm
from src.models.alchemy_model import UserOrm
from src.services.password_service import get_password_service


NAME_PERMISSION = "admin"

engine = create_engine(configs.postgres_dsn)
ps = get_password_service()
app = Typer()


def create_admin_user(session: Session, name: str, password: str) -> UserOrm:
    password_hash = asyncio_run(ps.compute_hash(password))

    admin_user = session.scalars(
        select(UserOrm).where(or_(UserOrm.login == name), UserOrm.is_deleted == False)  # noqa: E712
    ).first()

    if admin_user:
        raise Exit

    admin_user = UserOrm(login=name, password=password_hash)
    session.add(admin_user)

    return admin_user


@app.command()
def create_admin(
    login: str,
    password: str,
) -> None:
    with Session(engine) as pg_session:
        admin_permission = pg_session.scalars(
            select(PermissionOrm).where(PermissionOrm.name == NAME_PERMISSION)
        ).first()
        if not admin_permission:
            admin_permission = PermissionOrm(name=NAME_PERMISSION, description="admin permission allows everything")
            pg_session.add(admin_permission)

        admin_user = create_admin_user(pg_session, login, password)
        admin_user.permissions.append(admin_permission)
        pg_session.commit()


@app.command()
def delete_admin(login: str) -> None:
    with Session(engine) as session:
        admin_permission = session.scalars(select(PermissionOrm).where(PermissionOrm.name == NAME_PERMISSION)).first()
        num_admins = len(session.execute(select(UserOrm).where(UserOrm.permissions.contains(admin_permission))).all())
        admin_user = session.scalars(select(UserOrm).where(UserOrm.login == login)).first()
        if not admin_user:
            raise Exit

        if num_admins == 1:
            session.delete(admin_permission)

        session.delete(admin_user)
        session.commit()


if __name__ == "__main__":
    app()
