# AKiPS specific Exceptions


class AkipsError(Exception):
    """Exception raised for Errors return in AKiPS web api"""

    def __init__(self, message: str = "AKiPS web api returned error") -> None:
        self.message = message
        super().__init__(self.message)
