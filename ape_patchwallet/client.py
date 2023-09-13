
from ape.types import AddressType
import requests
import json
import os

# Local
from .exceptions import Forbidden, MissingAuthToken

# Models
from .models import SignMessageResponse, SignTransactionResponse, VerifyOTPResponse, SigninWithOTPResponse, TransactionData, User

# Constants
from .constants import PATCHWALLET_SUPPORTED_PROVIDERS as PROVIDERS
from .constants import PATCHWALLET_URLS as URLS

# Patch Wallet Client
class PatchClient:
  def __init__(
        self,
        user_id: str
      )-> None:
      
      # Parse the user ID
      self.user = User(id=user_id)      

  def get_address(self) -> AddressType:
    # Send request to Resolver API
    response = requests.post(
      URLS.get('resolver'), 
      headers={"Content-Type": "text/plain"}, 
      data=json.dumps({"userIds": self.user.id})
    )

    if response.status_code == 200:
      data = response.json()
      users = data.get("users")
      if users:
        user = users[0]
        address = user.get("accountAddress")
        if address:
          self.address = address
          return address
        else:
            raise ValueError("Address not found")
      else:
          raise ValueError("No users found")
    else:
        raise ValueError("API error")

  def get_bearer_token(self, force: bool = False) -> str:

    # Get credentials from environment variables
    data = {
        "client_id": os.environ.get("PATCHWALLET_CLIENT_ID"),
        "client_secret": os.environ.get("PATCHWALLET_CLIENT_SECRET")
    }

    # Send request to Patch Wallet API to authenticate and get the bearer token
    response = requests.post(
        URLS.get('auth'), 
        headers={"Content-Type": "application/x-www-form-urlencoded"}, 
        data=data
    )

    # Parse response
    result = response.json()
    access_token = result.get("access_token")
    if response.status_code != 200 or not access_token:
      raise Exception("Authentication failed")

    # Store the access token for future use in the keyring
    return access_token

  def user_auth(self) -> SigninWithOTPResponse:
    # Extract phone number from username
    if self.user.provider.type == 'user':
      phone = self.user.username
    else:
      raise ValueError('This method of authentication is not supported')
    # Prepare headers
    headers = {
      "Content-Type": "application/json"
    }
    # Send request to signinwithotp API
    response = requests.post(
      f"{URLS.get('signinwithotp')}", 
      data=json.dumps({"phone": "+" + phone}),
      headers=headers
    )
    # Handle response
    if response.status_code == 200:
      data = response.json()
      print(data)
      return SigninWithOTPResponse(**data)
    else:
      raise ValueError("API error")

  def verify_otp(self, code: int) -> VerifyOTPResponse:
    # Prepare headers
    headers = {
      "Content-Type": "application/json"
    }
    # Prepare data
    data = {
      "phone": "+" + self.user.username,
      "token": str(code)
    }
    
    # Send request to verifyotp API
    response = requests.post(
      f"{URLS.get('verifyotp')}", 
      headers=headers, 
      data=json.dumps(data)
    )
    # Handle response
    if response.status_code == 200:
      data = response.json()
        # Parse the response using the Pydantic model
      return VerifyOTPResponse(
        user=data['data']['user'],
        session=data['data']['session']
      )
    else:
      raise ValueError("API error")

  def sign_message(self, text: str) -> SignMessageResponse:

    # Prepare headers
    headers = {
      "Authorization": f"Bearer {self.bearer_token}",
      "Content-Type": "application/json"
    }

    # Prepare message data
    data = {
      "userId": self.user.id,
      "chain": self.chain_id,
      "data": text
    }

    # Send request to Kernel API
    response = requests.post(
      f"{URLS.get('kernel')}/sign-message", 
      headers=headers, 
      data=json.dumps(data)
    )

    # Parse response
    if response.status_code == 200:
      result = response.json()
      # Parse the response to the Pydantic model
      signature_response = SignMessageResponse(**result)
      return signature_response
    else:
      raise Exception("Failed to sign message")

  def tx(self, txn: TransactionData, bearer_token: str, jwt: str) -> SignTransactionResponse:
    headers = {}

    # Check for bearer token
    if bearer_token is None and self.user.provider.type == "app":
      raise MissingAuthToken("bearer token", self.user.provider.name)
    else:
      headers.update({"Authorization": f"Bearer {bearer_token}"})

    # Add header content type
    headers.update({"Content-Type": "application/json"})

    if jwt is None and self.user.provider.type == "user":
      raise MissingAuthToken("jwt token", self.user.provider.name)

    # Prepare transaction data
    data = {
      "userId": self.user.id,
      "chain": txn.chain,
      "to": txn.to,
      "value": [str(val) for val in txn.value],
      "data": txn.data,
      "auth": jwt if jwt is not None else "",
      "delegatecall": 1 if txn.delegate_call else 0
    }

    # Send request to Kernel API
    response = requests.post(
      f"{URLS.get('kernel')}/tx", 
      headers=headers, 
      data=json.dumps(data)
    )

    # Parse response
    if response.status_code == 200:
      result = response.json()
      # Parse the response to the Pydantic model
      transaction_response = SignTransactionResponse(**result)
      return transaction_response
    elif response.status_code == 403:
      raise Forbidden("You will need to reauthenticate the provider")
    else:
      response.raise_for_status()
