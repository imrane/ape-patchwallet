from ape import plugins

from ape_patchwallet.accounts import AccountContainer, PatchWalletAccount

@plugins.register(plugins.AccountPlugin)
def account_types():
    return AccountContainer, PatchWalletAccount# Add module top-level imports here
