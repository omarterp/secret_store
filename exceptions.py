from hvac.exception.VaultError import VaultError

class VaultAuthenticationError(VaultError):
    pass

class VaultAssumedRoleNotFoundError(VaultError):
    pass