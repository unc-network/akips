# AKiPS specific Exceptions


class AkipsError(Exception):
    """Exception raised for Errors return in AKiPS web api"""

    def __init__(self, message: str = "AKiPS web api returned error") -> None:
        self.message = message
        super().__init__(self.message)


class AkipsCredentialError(AkipsError, ValueError):
    """
    Exception raised when AKiPS credentials are missing or unusable.

    This is a configuration problem rather than a reply from AKiPS: it is
    raised before any request is made, so it can be caught at startup and
    reported as a settings error rather than a monitoring outage.

    It subclasses both AkipsError, so that catching everything this library
    raises still catches it, and ValueError, which is what a missing or
    unusable argument has always raised here.
    """

    def __init__(self, message: str = "AKiPS credentials are not configured") -> None:
        super().__init__(message)


class AkipsAuthenticationError(AkipsError):
    """
    Exception raised when AKiPS itself rejects the username and password.

    Distinct from AkipsCredentialError, which means credentials were missing
    or unusable and is raised without contacting the server. This one means a
    credential was sent and AKiPS refused it: the password may be wrong, or
    the application token may be invalid, revoked or expired.

    It subclasses AkipsError alone, deliberately not AkipsCredentialError:
    that one is also a ValueError, which suits a bad argument and not a
    reply from a server.

    Attributes:
        section (str | None): the API section that refused the credentials
        username (str | None): the account the request authenticated as,
            which is usually the useful half — a section needing api-rw and
            given api-ro fails here rather than anywhere more obvious

    username is None for token authentication.  Both are None when the
    exception is constructed without them.  There is
    no HTTP status worth carrying: AKiPS answers 200 to everything, errors
    included, which is why the reply body is what this library reads.
    """

    def __init__(
        self,
        message: str = "AKiPS rejected the credentials",
        section: str | None = None,
        username: str | None = None,
    ) -> None:
        self.section = section
        self.username = username
        super().__init__(message)


class AkipsPermissionError(AkipsError):
    """The application token lacks access to the API or to a write command.

    Distinct from AkipsAuthenticationError: the token was accepted, but its
    fixed permissions do not allow this call.  Create a new application with
    the required permissions in AKiPS to change that access.

    Attributes:
        section (str | None): the API section that refused access
    """

    def __init__(
        self,
        message: str = "The AKiPS application token lacks the required permission",
        section: str | None = None,
    ) -> None:
        self.section = section
        super().__init__(message)


class AkipsSectionDisabledError(AkipsError):
    """
    Exception raised when the API section is switched off on the server.

    For legacy password authentication, every section is disabled by default
    and each is enabled separately under
    Admin > API > Web API Settings.  The credentials were accepted, so this
    is a server configuration problem rather than anything wrong with the
    call, and it is the most common first-run failure.

    Attributes:
        section (str | None): the API section that is switched off, so a
            caller can name it without matching on the message, which is
            AKiPS's wording and may be reworded

    It is None when the exception is constructed without it.
    """

    def __init__(
        self,
        message: str = "The AKiPS API section is not enabled",
        section: str | None = None,
    ) -> None:
        self.section = section
        super().__init__(message)
