from fastapi import Response

from src.models.errors import ErrorBody


class MisdirectedRequestError(Exception):
    def __init__(self, detail: str) -> None:
        self.body = ErrorBody(detail=detail)


class ResponseError(Exception):
    def __init__(self, status_code: int, detail: str) -> None:
        self.status_code = status_code
        self.body = ErrorBody(detail=detail)


class JWTBannedError(Exception):
    def __init__(self, response: Response) -> None:
        self.response = response
