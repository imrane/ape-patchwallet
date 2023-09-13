import click
from datetime import datetime
from ape import accounts, networks
from ape_tokens import tokens
from ape.cli import (
  NetworkBoundCommand, 
  ape_cli_context,
  non_existing_alias_argument,
  existing_alias_argument,
  network_option
)
import keyring
import os

# Import local modules
from .accounts import PatchWalletAccount
from .client import PatchClient

@click.group(short_help="Manage Safe accounts and view Safe API data")
def cli():
  """
  Command-line helper for managing Patch Wallets. You can add Patch Wallets to your local accounts.
  """

@cli.command(name="list", cls=NetworkBoundCommand, short_help="Show locally-tracked Patch Wallets")
@ape_cli_context()
def _list(cli_ctx):
  patches = accounts.get_accounts_by_type(type_=PatchWalletAccount)
  num_of_accts = len(patches) 

  if num_of_accts == 0:
    cli_ctx.logger.warning("No Patch Wallets found.")
    return       
  
  header = f"Found {num_of_accts} Wallet"
  header += "s:" if num_of_accts > 1 else ":"
  click.echo(header)

  for account in patches:
    extras = []
    if account.alias:
      extras.append(f"alias: '{account.alias}'")

    extras_display = f" ({', '.join(extras)})" if extras else ""
    click.echo(f"  {account.address}{extras_display}")

@cli.command(cls=NetworkBoundCommand, short_help="Add a Patch Wallet to locally tracked Wallets")
@ape_cli_context()
@non_existing_alias_argument()
def add(cli_ctx, alias):
  """Add a Patch Wallet account to ape"""
  container = accounts.containers.get("patchwallet")
  container.save_account(alias=alias, address=PatchClient(alias).get_address())
  cli_ctx.logger.success(f"Account '{alias}' successfully added'.")

@cli.command(cls=NetworkBoundCommand, short_help="Authenticate a Patch Wallet")
@ape_cli_context()
@existing_alias_argument(account_type=PatchWalletAccount)
@click.argument("force", default="Forces a new app authentication token to be generated", required=False)
def auth(cli_ctx, alias, force):
  container = accounts.containers.get("patchwallet")
  account = container.load_account(alias=alias)
 
  if account.user.provider.type == "user":
    try:
      # Try user auth
      auth_response = account.auth.user()
      cli_ctx.logger.success("Check your messages for OTP code")
      # Get OTP code
      otp_code = click.prompt("Enter the OTP code", type=int)
      otp_verification_response = account.auth.verifyOTP(otp_code)
      # Log session time left and store jwt token in keyring
      expiry_time = datetime.fromtimestamp(int(otp_verification_response.session.expires_at)) - datetime.now()
      # Store the password in the keyring
      keyring.set_password(alias, os.environ.get("PATCHWALLET_PASS"), otp_verification_response.session.access_token)
      # Log success message
      cli_ctx.logger.success(f"Authentication for {alias} successful, token expires {expiry_time} from now")
    except Exception as e:
      cli_ctx.logger.error(f"Error during user authentication: {e}")
  else:
    try:
      auth_app_response = account.auth.app(force)
      # Store the password in the keyring
      keyring.set_password(account.user.provider.name, os.environ.get("PATCHWALLET_PASS"), auth_app_response)
      cli_ctx.logger.success("App authentication successful.")
    except Exception as e:
      cli_ctx.logger.error(f"Error during app authentication: {e}")
  

@cli.command(cls=NetworkBoundCommand, short_help="Remove a locally tracked Patch Wallet")
@ape_cli_context()
@existing_alias_argument(account_type=PatchWalletAccount)
def remove(cli_ctx, alias):
  """Remove a Patch Wallet account from ape"""
  container = accounts.containers.get("patchwallet")
  container.delete_account(alias)
  cli_ctx.logger.success(f"Account '{alias}' has been removed.")

def sign_message():
    pass

@cli.command(cls=NetworkBoundCommand, short_help="Remove a locally tracked Patch Wallet")
@ape_cli_context()
@existing_alias_argument(account_type=PatchWalletAccount)
def transfer(cli_ctx, alias):
  with networks.parse_network_choice("arbitrum:mainnet:alchemy") as provider:
    """Transfer funds from a Patch Wallet account"""
    container = accounts.containers.get("patchwallet")
    account = container.load_account(alias=alias)
    # Get the bearer token from the keyring
    bearer_token = keyring.get_password(account.user.provider.name, os.environ.get("PATCHWALLET_PASS"))
    
    address = "0x9C549499f1f631a264a80F82dd3db608b211E9c6"
    # Get the token address
    usdc = tokens["USDC"]
    print(usdc.address)
    usdc.transfer(address, 100000000000000, bearer_token=bearer_token)

    #account.transfer(address, 100000000000000, bearer_token=bearer_token)
    
  pass