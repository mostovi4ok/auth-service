from pydantic import BaseModel


class ErrorBody(BaseModel):
    detail: str
