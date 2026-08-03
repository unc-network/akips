# AKiPS specific Exceptions


class AkipsError(Exception):
    """Exception raised for Errors return in AKiPS web api"""

    def __init__(self, message: str = "AKiPS web api returned error") -> None:
        self.message = message
        super().__init__(self.message)


class AkipsCredentialError(AkipsError, ValueError):
    """
    Exception raised when the AKiPS account a call needs has no password.

    This is a configuration problem rather than a reply from AKiPS: it is
    raised before any request is made, so it can be caught at startup and
    reported as a settings error rather than a monitoring outage.

    It subclasses both AkipsError, so that catching everything this library
    raises still catches it, and ValueError, which is what a missing or
    unusable argument has always raised here.
    """

    def __init__(self, message: str = "AKiPS credentials are not configured") -> None:
        super().__init__(message)
