import os
import getpass
from eth_utils import is_0x_prefixed, to_bytes
from hexbytes import HexBytes

def get_password(self) -> str:
  PATCHWALLET_PASS = os.environ.get("PATCHWALLET_PASS")
  if not PATCHWALLET_PASS:
    PATCHWALLET_PASS = getpass.getpass("Enter Patchwallet Password: ")
  return PATCHWALLET_PASS

def _to_bytes(val):
  if val is None:
    return b""
  elif isinstance(val, str) and is_0x_prefixed(val):
    return to_bytes(hexstr=val)
  elif isinstance(val, str):
    return to_bytes(text=val)
  elif isinstance(val, HexBytes):
    return bytes(val)
  else:
    return to_bytes(val)