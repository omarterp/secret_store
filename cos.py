"""
This module provides a singleton class `SecretStore` for managing interactions with a Vault server.

It supports different environments and authentication methods to securely access and manage secrets.
The `SecretStore` class ensures that only a single instance is created per environment, handling the
initialization and authentication processes with the Vault server using the HVAC client library.

Classes:
    AuthMethod (Enum): Defines the supported authentication methods.
    Environment (Enum): Enumerates the environments the SecretStore client can operate in.
    SecretStore: A singleton class for interacting with the Vault server.

Exceptions:
    VaultAuthenticationError: Raised when authentication with the Vault server fails.
    VaultAssumedRoleNotFoundError: Raised when the assumed role is not found during authentication.

Dependencies:
    hvac: HashiCorp Vault client for Python.
    boto3: Amazon Web Services (AWS) SDK for Python.
    requests: HTTP library for Python.

Usage:
    The `SecretStore` class can be used to obtain a client instance configured for a specific
    environment and authenticated using a specified method. This instance provides
    methods to interact with the Vault server, such as retrieving secrets.
"""
import hvac

import hvac.exceptions
import boto3
import getpass
from hvac.exceptions import VaultAssumedRoleNotFoundError
from requests.exceptions import ConnectionError, Timeout

from enum import Enum

from .config import Config
from .logger import logger
from .exceptions import VaultAuthenticationError, VaultAssumedRoleNotFoundError

class AuthMethod(Enum):
    """Defines the supported authentication methods for the SecretStore."""    
    IAM = "iam"
    LDAP = "ldap"

class Environment(Enum):
    """Enumerates the environments the SecretStore client can operate in."""    
    LOCAL = "local"
    DEV = "dev"
    QA = "qa"
    PROD = "prod"

class SecretStore:
    """A singleton class for managing interactions with a Vault server.

    This class ensures that only one instance is created for a given environment.
    It handles authentication with the Vault server using specified authentication methods.

    Attributes:
        environment (Environment): The environment for which the SecretStore client is configured.
        vault_addr (str): The URL of the Vault server.
        client (hvac.Client): The HVAC client instance for interacting with Vault.
        auth_method (AuthMethod): The authentication method used for Vault.

    Raises:
        VaultAuthenticationError: If authentication with Vault fails.
    """    
    __instance = None

    def __new__(cls):
        """Create a new instance of the SecretStore class or return the existing instance.

        Args:
            environment (Environment): The environment for which to configure the SecretStore client.

        Returns:
            SecretStore: The singleton instance of the SecretStore class.
        """        
        if cls.__instance is None:
            cls.__instance = super(SecretStore, cls).__new__(cls)
            cls.__instance.__initialized = False
        return cls.__instance

    def __init__(self, environment=Environment.LOCAL):
        """Initialize the SecretStore class instance.

        Initializes the HVAC client and authenticates with the Vault server.
        This method is called only once during the first instantiation.

        Args:
            environment (Environment): The environment for which to configure the SecretStore client.
        """     
        if self.__initialized:
            return
        self.environment = environment
        self.vault_addr = Config.get_vault_url(self.environment.value)
        self.client = hvac.Client(url=self.vault_addr)
        self.auth_method = self._get_auth_method()
        self.authenticate()
        self.__initialized = True


    @staticmethod
    def get_instance(environment=Environment.LOCAL):
        """Get the singleton instance of the SecretStore class for the specified environment.

        Args:
            environment (Environment): The environment for which to get the SecretStore instance.

        Returns:
            SecretStore: The singleton instance of the SecretStore class.
        """
        return SecretStore(environment)


    @property
    def client(self):
        """Get the HVAC client instance for interacting with the Vault server."""
        if not self.client.is_authenticated():
            self.authenticate()  # Re-authenticate if not authenticated
        return self.client


    def authenticate(self):
        """Authenticate with the Vault server using the specified method."""
        try:
            if self.auth_method == "iam":
                session = boto3.Session()
                sts_client = session.client('sts')
                caller_identity = sts_client.get_caller_identity()
                arn = caller_identity['Arn']

                # Extract the role name from the ARN if it's an assumed role
                if ':assumed-role/' in arn:
                    role_name = arn.split(':')[5].split('/')[1]
                else:
                    raise VaultAssumedRoleNotFoundError("The current identity is not an assumed role.")

                creds = session.get_credentials().get_frozen_credentials()
                region_name = session.region_name  # Dynamically get the region
                
                self.client.auth.aws.iam_login(
                    access_key=creds.access_key,
                    secret_key=creds.secret_key,
                    session_token=creds.token,
                    role=role_name,
                    use_token=True,
                    region=region_name,  # Use the dynamically determined region
                    mount_point='prod-iam'
                )
                logger.info("Authenticated with IAM")
            elif self.auth_method == "ldap":
                username = input("Enter your LDAP username: ")
                password = getpass.getpass("Enter your LDAP password: ")

                # Here the mount_point parameter corresponds to the path provided when enabling the backend
                self.client.auth.ldap.login(
                    username=username,
                    password=password,
                    mount_point='prod-ldap'
                )
                logger.info("Authenticated with LDAP")
            else:
                raise VaultAuthenticationError("Invalid authentication method")
        except VaultAuthenticationError as e:
            logger.error(f"Authentication failed: {e}")
            raise
        except Exception as e:  # Catch general errors
            logger.exception(f"Authentication failed with unexpected error: {e}")
            raise VaultAuthenticationError("Authentication failed") from e


    def _get_auth_method(self):
        """Determines the authentication method based on the environment."""
        if self.environment == Environment.LOCAL:
            return AuthMethod.LDAP
        else:
            return AuthMethod.IAM


    def read_secret(self, path):
        """Reads a secret from Vault at the given path."""
        try:
            read_response = self.client.secrets.kv.v2.read_secret_version(
                mount_point="secret",  # Adjust if using a different mount point
                path=path
            )
            return read_response["data"]["data"]  # Extract the secret data
        except hvac.exceptions.InvalidPath as e:
            logger.error(f"Secret not found at path: {path}. Error: {e}")
        except hvac.exceptions.Forbidden as e:
            logger.error(f"Access denied to path: {path}. Error: {e}")
        except hvac.exceptions.Unauthorized as e:
            logger.error(f"Client unauthorized, check authentication. Error: {e}")
        except hvac.exceptions.VaultError as e:
            logger.error(f"Vault error occurred: {e}")
        except ConnectionError as e:
            logger.error(f"Failed to connect to Vault server. Error: {e}")
        except Timeout as e:
            logger.error(f"Connection to Vault server timed out. Error: {e}")
        except Exception as e:
            logger.error(f"An unexpected error occurred: {e}")
        raise hvac.exceptions.VaultError("Failed to read secret")
