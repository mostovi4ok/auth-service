from src.models.errors import ErrorBody


class ResponseError(Exception):
    def __init__(self, detail: str) -> None:
        self.body = ErrorBody(detail=detail)
