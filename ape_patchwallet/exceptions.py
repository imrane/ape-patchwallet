from ape.exceptions import ApeException
from requests.exceptions import HTTPError

class Forbidden(HTTPError):
  """Exception raised when a 403 Forbidden error is encountered."""

  def __init__(self, *args, **kwargs):
    super().__init__(403, *args, **kwargs)

class MissingAuthToken(ApeException):
  """Exception raised when an authentication token is missing."""

  def __init__(self, token_type: str, provider_name: str):
    message = f"You need to pass a {token_type} for {provider_name} provider"
    super().__init__(message)