PATCHWALLET_URLS = {    
  "kernel": "https://paymagicapi.com/v1/kernel",
  "resolver": "https://paymagicapi.com/v1/resolver",
  "auth": "https://paymagicapi.com/v1/auth",
  "signinwithotp": "https://auth.paymagicapi.com/functions/v1/signInWithOTP",
  "verifyotp": "https://auth.paymagicapi.com/functions/v1/verifyOTP"
}

PATCHWALLET_SUPPORTED_CHAINS = {
  "ethereum": {
    "id": 1,
    "type": "prod",
    "name": "eth",
  },
  "abritrum": {
    "id": 42161,
    "type": "prod",
    "name": "arb1",
  },
  "polygon": {
    "id": 42161,
    "type": "prod",
    "name": "arb1",      
  }
}

PATCHWALLET_SUPPORTED_PROVIDERS = [
    {
        "name": "tel",
        "type": "user",
    },
    {
        "name": "lang",
        "type": "app",
    }
]