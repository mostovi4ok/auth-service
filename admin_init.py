from asyncio import run as asyncio_run

from sqlalchemy import create_engine
from sqlalchemy import or_
from sqlalchemy import select
from sqlalchemy.orm import Session
from typer import Exit
from typer import Typer

from src.core.config import configs
from src.models.alchemy_model import RightOrm
from src.models.alchemy_model import UserOrm
from src.services.password_service import get_password_service


NAME_RIGHT = "admin"

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
        admin_right = pg_session.scalars(select(RightOrm).where(RightOrm.name == NAME_RIGHT)).first()
        if not admin_right:
            admin_right = RightOrm(name=NAME_RIGHT, description="admin right allows everything")
            pg_session.add(admin_right)

        admin_user = create_admin_user(pg_session, login, password)
        admin_user.rights.append(admin_right)
        pg_session.commit()


@app.command()
def delete_admin(login: str) -> None:
    with Session(engine) as session:
        admin_right = session.scalars(select(RightOrm).where(RightOrm.name == NAME_RIGHT)).first()
        num_admins = len(session.execute(select(UserOrm).where(UserOrm.rights.contains(admin_right))).all())
        admin_user = session.scalars(select(UserOrm).where(UserOrm.login == login)).first()
        if not admin_user:
            raise Exit

        if num_admins == 1:
            session.delete(admin_right)

        session.delete(admin_user)
        session.commit()


if __name__ == "__main__":
    app()
