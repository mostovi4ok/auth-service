from contextvars import ContextVar


RequestId: ContextVar[str] = ContextVar("RequestId", default="None")
RequesMethod: ContextVar[str] = ContextVar("RequesMethod", default="None")
RequesUrl: ContextVar[str] = ContextVar("RequesUrl", default="None")
