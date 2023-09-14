import json
import os
import getpass
import keyring

# Ape
from ape.api import AccountAPI, AccountContainerAPI, TransactionAPI, ReceiptAPI
from ape.types import AddressType, MessageSignature, SignableMessage
from ape.logging import logger

# Utils
from typing import Iterator, Optional
from pathlib import Path
from eth_utils import to_hex

# Local
from .client import PatchClient 
from .models import TransactionData, User, SigninWithOTPResponse, VerifyOTPResponse
from .exceptions import Forbidden
from .constants import PATCHWALLET_SUPPORTED_CHAINS, PATCHWALLET_SUPPORTED_PROVIDERS as PROVIDERS

# Reorganize CHAINS by id
CHAINS = {chain['id']: chain for chain in PATCHWALLET_SUPPORTED_CHAINS.values()}
KEYRING_PASS = os.environ.get("PATCHWALLET_PASS")

class AccountContainer(AccountContainerAPI):
  @property
  def accounts(self) -> Iterator[AccountAPI]:
    for account_file in self._account_files:
      yield PatchWalletAccount(container=self, account_file_path=account_file)

  @property
  def _account_files(self) -> Iterator[Path]:
    return self.data_folder.glob("*.json")
    
  @property
  def aliases(self) -> Iterator[str]:
    for p in self._account_files:
      yield p.stem
    
  def __len__(self) -> int:
    return len([*self._account_files])
    
  def save_account(self, alias: str, address: AddressType):
    account_data = {"address": address}
    path = self.data_folder.joinpath(f"{alias}.json")
    path.write_text(json.dumps(account_data))

  def load_account(self, alias: str) -> "PatchWalletAccount":
    account_path = self.data_folder.joinpath(f"{alias}.json")
    return PatchWalletAccount(account_file_path=account_path)

  def delete_account(self, alias: str):
    path = self.data_folder.joinpath(f"{alias}.json")

    if path.exists():
      path.unlink()

class Authenticate:
  def __init__(self, client):
    self._client = client

  @property
  def bearer_token(self) -> str:
    return keyring.get_password(self._client.user.provider.name, KEYRING_PASS)

  @property
  def jwt(self) -> str:
    return keyring.get_password(self._client.user.id, KEYRING_PASS)

  def user(self) -> SigninWithOTPResponse:
    return self._client.user_auth()

  def verifyOTP(self, code: int) -> VerifyOTPResponse:
    response = self._client.verify_otp(code)
    if response.session.access_token:
      print('Saving jwt on keyring...')
      keyring.set_password(self._client.user.id, KEYRING_PASS, response.session.access_token)
    return response

  def app(self, force: bool = False) -> str:
    response = self._client.get_bearer_token(force)
    if response:
      print('Saving bearer_token on keyring...')
      keyring.set_password(self._client.user.provider.name, KEYRING_PASS, response)
    return response

class PatchWalletAccount(AccountAPI):
  account_file_path: Path

  @property
  def alias(self) -> str:
    return self.account_file_path.stem
    
  @property
  def user(self) -> User:
    return self._client.user
  
  @property
  def auth(self) -> Authenticate:
    return Authenticate(self._client)
    
  @property
  def _client(self) -> PatchClient:
    return PatchClient(user_id=self.alias)

  @property
  def address(self) -> AddressType:
    ecosystem = self.network_manager.get_ecosystem("ethereum")
    return ecosystem.decode_address(self.account_file["address"])
        
  @property
  def account_file(self) -> dict:
    return json.loads(self.account_file_path.read_text())
    
  @property
  def provider_type(self) -> str:
    # return provider type based on provider name
    return [provider['type'] for provider in PROVIDERS if provider['name'] == self.user.provider][0]
    
  def sign_message(self, msg: SignableMessage, **kwargs) -> Optional[MessageSignature]:

    try:
      response = self._client.sign_message(msg.body, self.auth.bearer_token)
      # Log the transaction hash
      logger.success(f"Successful with signature: {response.signature}")
      # Return the ReceiptAPI
      return response
    except Forbidden as e:
      # Raise error
      raise ValueError("You need to reauthenticate the provider")
    except Exception as e:
      # Raise error
      raise ValueError("API error")
    
  def sign_transaction(self, txn: TransactionAPI) -> Optional[TransactionAPI]:
    return super().sign_transaction(txn)

  def call(self, txn: TransactionAPI, **kwargs) -> Optional[ReceiptAPI]:
    # Add chain ID to the transaction
    txn.chain_id = self.provider.chain_id

    # Check to see if the chain is supported, throw error if not
    if txn.chain_id not in CHAINS:
      raise ValueError(f"Chain with id {txn.chain_id} is not supported.")
    
    # Get the bearer token and jwt
    bearer_token = self.auth.bearer_token
    jwt = self.auth.jwt

    # Convert the TransactionAPI to the TransactionData model

    txn_data = TransactionData(
      chain=CHAINS[txn.chain_id]['name'],
      to=[txn.receiver],
      value=[txn.value],
      data=[to_hex(txn.data)],
      delegate_call=kwargs.get('delegate_call', False)
    )
    
    # Use the sign_transaction method from the client.py file to execute the transaction
    try:
      response = self._client.tx(txn_data, bearer_token, jwt)
      # Log the transaction hash
      logger.success(f"Successful transaction with hash: {response.txHash}")
      # Return the ReceiptAPI
      return {"txn_hash": response.txHash, "status": 1, "transaction": txn}
    except Forbidden as e:
      # Raise error 
      raise ValueError("You need to reauthenticate the provider")
    except Exception as e:
      # Raise error
      raise ValueError("API error")
   