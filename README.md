# Quick Start

Account plugin for the [Patch Wallet SDK][1]

## Dependencies

* [python3](https://www.python.org/downloads) version 3.8 up to 3.11.

## Installation

### via `pip`

You can install the latest release via [`pip`](https://pypi.org/project/pip/):

```bash
pip install ape-patchwallet
```

### via `setuptools`

You can clone the repository and use [`setuptools`](https://github.com/pypa/setuptools) for the most up-to-date version:

```bash
git clone https://github.com/ApeWorX/ape-patchwallet.git
cd ape-patchwallet
python3 setup.py install
```

## Quick Usage
### Export Variables
You'll need to export the following environment variables. Pass will be used to encrypt secrets using keyring.
```bash
# For custom providers...
export PATCHWALLET_[PROVIDER]_CLIENT_ID=""
export PATCHWALLET_[PROVIDER]_CLIENT_SECRET=""
# Optional
export PATCHWALLET_PASS=""
# Refresh
source ~/.zshrc
```

### Via CLI

```bash
ape patchwallet add <alias>
ape patchwallet remove <alias>
ape patchwallet auth <alias>
ape patchwallet list
```
### Via Python
```python
patch = accounts.load("tel:14168906789")
```

## Development

This project is in development and should be considered a beta.
Things might not be in their final state and breaking changes may occur.
Comments, questions, criticisms and pull requests are welcomed.

[1]: https://docs.patchwallet.com

