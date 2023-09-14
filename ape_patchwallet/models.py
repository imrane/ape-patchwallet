from typing import Optional, List, Dict, Any
from pydantic import BaseModel, validator
from .constants import PATCHWALLET_SUPPORTED_PROVIDERS as PROVIDERS

# Patch wallet models
class TransactionData(BaseModel):
  chain: str
  to: List[str]
  value: List[int]
  data: List[str]
  delegate_call: bool = False

# Patch wallet responses
class SignMessageResponse(BaseModel):
  hash: str
  signature: str
  type: str

class SignTransactionResponse(BaseModel):
  txHash: str

class SigninWithOTPResponse(BaseModel):
  message: str
  user: Optional[str] = None
  session: Optional[str] = None

class UserData(BaseModel):
  id: str
  role: str
  email: str
  phone: str

class SessionData(BaseModel):
  access_token: str
  expires_in: int
  expires_at: str

class VerifyOTPResponse(BaseModel):
  user: UserData
  session: SessionData  

# Internal Models
class Provider(BaseModel):
  name: str
  type: str  

class User(BaseModel):
  id: str
  provider: Provider
  username: str

  @validator('username')
  def validate_username(cls, v, values, **kwargs):
    if values.get('provider') == 'tel':
      if len(v) != 11 or not v.startswith('1'):
        raise ValueError('Invalid phone number')
    return v

  def __init__(self, id: str):
    provider_name, username = id.split(':')
    # use the providers array to match the provider name and get the type, store them in provider
    provider_type = [provider for provider in PROVIDERS if provider['name'] == provider_name][0]['type']
    # store the provider model
    provider = Provider(name=provider_name, type=provider_type)
    super().__init__(id=id, provider=provider, username=username)