"""Domain and HTTP-mapped exceptions for UniteCare authentication and authorization."""

from fastapi import HTTPException, status


class UniteCareSecurityException(HTTPException):
    """Base exception for UniteCare security errors ensuring consistent, safe responses."""

    def __init__(self, status_code: int, detail: str):
        super().__init__(status_code=status_code, detail=detail)


class AuthenticationFailedException(UniteCareSecurityException):
    """Raised when authentication fails due to invalid credentials, tokens, or sessions."""

    def __init__(self, detail: str = "Invalid email or password."):
        super().__init__(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail)


class AccountInactiveException(UniteCareSecurityException):
    """Raised when a user account is suspended or disabled."""

    def __init__(self, detail: str = "Account is inactive, suspended, or disabled."):
        super().__init__(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail)


class EmailAlreadyExistsException(UniteCareSecurityException):
    """Raised on user registration when the normalized email is already in use."""

    def __init__(self, detail: str = "An account with this email already exists."):
        super().__init__(status_code=status.HTTP_409_CONFLICT, detail=detail)


class PermissionDeniedException(UniteCareSecurityException):
    """Raised when an authenticated actor lacks the required system permission."""

    def __init__(self, detail: str = "Access forbidden: insufficient permissions."):
        super().__init__(status_code=status.HTTP_403_FORBIDDEN, detail=detail)
