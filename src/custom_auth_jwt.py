from async_fastapi_jwt_auth.auth_jwt import AuthJWT
from async_fastapi_jwt_auth.auth_jwt import AuthJWTBearer
from fastapi import Request
from fastapi import Response

from src.models.cookie import Cookie
from src.models.jwt import RawToken


class CustomAuthJWT(AuthJWT):
    _access_expire_key = "access_expire"
    _refresh_expire_key = "refresh_expire"

    async def set_cookies(self, cookie: Cookie, response: Response | None = None) -> None:
        response = response or self._response  # pyright: ignore[reportUnknownVariableType, reportUnknownMemberType, reportAttributeAccessIssue]
        response.set_cookie(**cookie.model_dump())  # pyright: ignore[reportUnknownMemberType]

    @property
    def token(self) -> str:
        token = self._token
        assert token is not None
        return token

    async def set_access_cookies(
        self, encoded_access_token: str, response: Response | None = None, max_age: int | None = None
    ) -> None:
        await super().set_access_cookies(encoded_access_token, response, max_age)
        raw_jwt = await self.get_raw_jwt(encoded_access_token)
        assert raw_jwt is not None
        raw_token = RawToken.model_validate(raw_jwt)
        response = response or self._response  # pyright: ignore[reportUnknownVariableType, reportUnknownMemberType, reportAttributeAccessIssue]
        response.set_cookie(  # pyright: ignore[reportUnknownMemberType]
            **Cookie(key=self._access_expire_key, value=str(raw_token.exp), samesite=None, max_age=max_age).model_dump()
        )

    async def set_refresh_cookies(
        self, encoded_refresh_token: str, response: Response | None = None, max_age: int | None = None
    ) -> None:
        await super().set_refresh_cookies(encoded_refresh_token, response, max_age)
        raw_jwt = await self.get_raw_jwt(encoded_refresh_token)
        assert raw_jwt is not None
        raw_token = RawToken.model_validate(raw_jwt)
        response = response or self._response  # pyright: ignore[reportUnknownVariableType, reportUnknownMemberType, reportAttributeAccessIssue]
        response.set_cookie(  # pyright: ignore[reportUnknownMemberType]
            **Cookie(
                key=self._refresh_expire_key, value=str(raw_token.exp), samesite=None, max_age=max_age
            ).model_dump()
        )

    async def unset_jwt_cookies(self, response: Response | None = None) -> None:
        await super().unset_jwt_cookies(response)
        response = response or self._response  # pyright: ignore[reportUnknownVariableType, reportUnknownMemberType, reportAttributeAccessIssue]

        response.delete_cookie(  # pyright: ignore[reportUnknownMemberType]
            self._access_expire_key,
            path=self._access_cookie_path,
            domain=self._cookie_domain,
        )
        response.delete_cookie(  # pyright: ignore[reportUnknownMemberType]
            self._refresh_expire_key,
            path=self._access_cookie_path,
            domain=self._cookie_domain,
        )


class CustomAuthJWTBearer(AuthJWTBearer):
    def __call__(self, req: Request = None, res: Response = None) -> CustomAuthJWT:  # pyright: ignore[reportArgumentType]
        return CustomAuthJWT(req, res)
