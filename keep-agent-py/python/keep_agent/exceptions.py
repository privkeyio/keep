from typing import Optional


class KeepAgentError(Exception):
    pass


class SessionExpired(KeepAgentError):
    pass


class SessionNotFound(KeepAgentError):
    pass


class RateLimitExceeded(KeepAgentError):
    def __init__(self, message: str, retry_after_secs: Optional[int] = None):
        super().__init__(message)
        self.retry_after_secs = retry_after_secs


class ScopeViolation(KeepAgentError):
    pass


class PolicyDenied(KeepAgentError):
    pass


class AmountExceeded(KeepAgentError):
    def __init__(self, message: str, requested: Optional[int] = None, limit: Optional[int] = None):
        super().__init__(message)
        self.requested = requested
        self.limit = limit


class AddressNotAllowed(KeepAgentError):
    pass


class EventKindNotAllowed(KeepAgentError):
    def __init__(self, message: str, kind: Optional[int] = None):
        super().__init__(message)
        self.kind = kind


class OperationNotAllowed(KeepAgentError):
    pass


class KeepAgentConnectionError(KeepAgentError):
    pass


class AuthError(KeepAgentError):
    pass


class InvalidToken(KeepAgentError):
    pass


class SessionDenied(KeepAgentError):
    pass
