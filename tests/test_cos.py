import pytest
import hvac
from unittest import TestCase
from unittest.mock import patch, MagicMock
from requests.exceptions import ConnectionError, Timeout, InvalidURL
from cos import SecretStore, AuthMethod, Environment, VaultAuthenticationError, logger



class TestSecretStore(TestCase):

    @pytest.mark.parametrize(
        "environment, auth_method",
        [
            (Environment.LOCAL, AuthMethod.LDAP),       
            (Environment.DEV, AuthMethod.IAM),
            (Environment.QA, AuthMethod.IAM),            
            (Environment.PROD, AuthMethod.IAM),
        ]
    )
    def setUp(self, environment, auth_method):
        self.environment = environment
        self.auth_method = auth_method
        self.path = "test/secret"
        self.mock_data = {"data": {"data": "mock_secret"}}


    @patch("cos.SecretStore.client")
    @patch("cos.logger")
    def test_secret_store_singleton(self, mock_client, mock_logger, reset_secret_store_instance):
        first_instance = SecretStore(environment=self.environment, auth_method=self.auth_method)
        second_instance = SecretStore(environment=self.environment, auth_method=self.auth_method)
        assert first_instance is second_instance


    @patch("cos.SecretStore.client")
    @patch("cos.logger")
    def test_authentication_success(self, mock_client, mock_logger, reset_secret_store_instance):
        # Mock successful authentication
        mock_client.return_value.is_authenticated.return_value = True
        secret_store_instance = SecretStore(environment=self.environment, auth_method=self.auth_method)
        assert secret_store_instance.client.is_authenticated()


    @patch("cos.SecretStore.client")
    @patch("cos.logger")
    def test_authentication_failure(self, mock_client, mock_logger, reset_secret_store_instance):
        # Mock authentication failure
        mock_client.return_value.is_authenticated.return_value = False
        with pytest.raises(VaultAuthenticationError):
            SecretStore(environment=self.environment, auth_method=self.auth_method)


    @patch("cos.SecretStore.client")
    @patch("cos.logger")
    def test_get_secret_success(self, mock_client, mock_logger, reset_secret_store_instance):
        secret_store = SecretStore(environment=self.environment, auth_method=self.auth_method)
        secret_store.set_secret("test_key", "test_value")
        secret = secret_store.read_secret("test_key")
        assert secret == "mock_secret"


    @patch("cos.SecretStore.client")
    @patch("cos.logger")
    def test_get_secret_nonexistent(self, mock_client, mock_logger, reset_secret_store_instance):
        secret_store = SecretStore(environment=self.environment, auth_method=self.auth_method)
        secret = secret_store.read_secret("nonexistent_key")
        assert secret is None


    @patch("cos.SecretStore.client")
    @patch("cos.logger")
    def test_operation_requires_authentication(self, mock_client, mock_logger, reset_secret_store_instance):
        # Assuming SecretStore has a method to check if it's authenticated
        secret_store = SecretStore(environment=self.environment, auth_method=self.auth_method)
        mock_client.return_value.is_authenticated.return_value = False
        with pytest.raises(VaultAuthenticationError):
            secret_store.read_secret("test_key")


    @patch("cos.SecretStore.client")
    @patch("cos.logger")
    def test_read_secret_success(self, mock_client, mock_logger, reset_secret_store_instance):
        mock_client.secrets.kv.v2.read_secret_version.return_value = self.mock_data
        result = self.secret_store.read_secret(self.path)
        self.assertEqual(result, "mock_secret")
        mock_logger.error.assert_called()


    @patch("cos.SecretStore.client")
    @patch("cos.logger")
    def test_read_secret_invalid_path(self, mock_client, mock_logger, reset_secret_store_instance):
        mock_client.secrets.kv.v2.read_secret_version.side_effect = hvac.exceptions.InvalidPath()
        with self.assertRaises(hvac.exceptions.VaultError):
            self.secret_store.read_secret(self.path)
        mock_logger.error.assert_called()


    @patch("cos.SecretStore.client")
    @patch("cos.logger")
    def test_read_secret_forbidden(self, mock_client, mock_logger, reset_secret_store_instance):
        mock_client.secrets.kv.v2.read_secret_version.side_effect = hvac.exceptions.Forbidden()
        with self.assertRaises(hvac.exceptions.VaultError):
            self.secret_store.read_secret(self.path)
        mock_logger.error.assert_called()


    @patch("cos.SecretStore.client")
    @patch("cos.logger")
    def test_read_secret_unauthorized(self, mock_client, mock_logger, reset_secret_store_instance):
        mock_client.secrets.kv.v2.read_secret_version.side_effect = hvac.exceptions.Unauthorized()
        with self.assertRaises(hvac.exceptions.VaultError):
            self.secret_store.read_secret(self.path)
        mock_logger.error.assert_called()


    @patch("cos.SecretStore.client")
    @patch("cos.logger")
    def test_read_secret_vault_error(self, mock_client, mock_logger, reset_secret_store_instance):
        mock_client.secrets.kv.v2.read_secret_version.side_effect = hvac.exceptions.VaultError()
        with self.assertRaises(hvac.exceptions.VaultError):
            self.secret_store.read_secret(self.path)
        mock_logger.error.assert_called()


    @patch("cos.SecretStore.client")
    @patch("cos.logger")
    def test_read_secret_connection_error(self, mock_client, mock_logger, reset_secret_store_instance):
        mock_client.secrets.kv.v2.read_secret_version.side_effect = ConnectionError()
        with self.assertRaises(hvac.exceptions.VaultError):
            self.secret_store.read_secret(self.path)
        mock_logger.error.assert_called()


    @patch("cos.SecretStore.client")
    @patch("cos.logger")
    def test_read_secret_timeout(self, mock_client, mock_logger, reset_secret_store_instance):
        mock_client.secrets.kv.v2.read_secret_version.side_effect = Timeout()
        with self.assertRaises(hvac.exceptions.VaultError):
            self.secret_store.read_secret(self.path)
        mock_logger.error.assert_called()


    @patch("cos.SecretStore.client")
    @patch("cos.logger")
    def test_read_secret_unexpected_error(self, mock_client, mock_logger, reset_secret_store_instance):
        mock_client.secrets.kv.v2.read_secret_version.side_effect = Exception("Unexpected")
        with self.assertRaises(hvac.exceptions.VaultError):
            self.secret_store.read_secret(self.path)
        mock_logger.error.assert_called()

    @patch("cos.SecretStore.client")
    @patch("cos.logger")
    @pytest.mark.parametrize(
        "side_effect, expected_exception",
        [
            (hvac.exceptions.InvalidRequest(), hvac.exceptions.InvalidRequest),  # Invalid credentials
            (hvac.exceptions.Unauthorized(), hvac.exceptions.Unauthorized),    # Permission errors
            (ConnectionError(), VaultAuthenticationError),                       # Network issues
            (Timeout(), VaultAuthenticationError),                              # Timeout
            (InvalidURL(), VaultAuthenticationError),                          # Bad URL
            (Exception("Unexpected Error"), VaultAuthenticationError),         # General exception
        ],
        ids=[
            "InvalidRequest",
            "Unauthorized",
            "ConnectionError",
            "Timeout",
            "InvalidURL",
            "UnexpectedError"
        ]
    )
    @pytest.mark.parametrize(
        "environment, auth_method, side_effect, expected_exception",
        [
            # Invalid credentials            
            (Environment.DEV, AuthMethod.IAM, hvac.exceptions.InvalidRequest(), hvac.exceptions.InvalidRequest),
            (Environment.QA, AuthMethod.IAM, hvac.exceptions.InvalidRequest(), hvac.exceptions.InvalidRequest),
            (Environment.PROD, AuthMethod.IAM, hvac.exceptions.InvalidRequest(), hvac.exceptions.InvalidRequest),
            # Permission errors
            (Environment.DEV, AuthMethod.IAM, hvac.exceptions.Unauthorized(), hvac.exceptions.Unauthorized),
            (Environment.QA, AuthMethod.IAM, hvac.exceptions.Unauthorized(), hvac.exceptions.Unauthorized),
            (Environment.PROD, AuthMethod.IAM, hvac.exceptions.Unauthorized(), hvac.exceptions.Unauthorized),
            # Network issues
            (Environment.DEV, AuthMethod.IAM, ConnectionError(), VaultAuthenticationError),
            (Environment.QA, AuthMethod.IAM, ConnectionError(), VaultAuthenticationError),
            (Environment.PROD, AuthMethod.IAM, ConnectionError(), VaultAuthenticationError),
            # Timeout
            (Environment.DEV, AuthMethod.IAM, Timeout(), VaultAuthenticationError),
            (Environment.QA, AuthMethod.IAM, Timeout(), VaultAuthenticationError),
            (Environment.PROD, AuthMethod.IAM, Timeout(), VaultAuthenticationError),
            # Bad URL
            (Environment.DEV, AuthMethod.IAM, InvalidURL(), VaultAuthenticationError), 
            (Environment.QA, AuthMethod.IAM, InvalidURL(), VaultAuthenticationError),
            (Environment.PROD, AuthMethod.IAM, InvalidURL(), VaultAuthenticationError),
            # Invalid Token
            (Environment.DEV, AuthMethod.IAM, hvac.exceptions.Forbidden(), VaultAuthenticationError),
            (Environment.QA, AuthMethod.IAM, hvac.exceptions.Forbidden(), VaultAuthenticationError),
            (Environment.PROD, AuthMethod.IAM, hvac.exceptions.Forbidden(), VaultAuthenticationError),
            # Invalid LDAP Credentials
            (Environment.LOCAL, AuthMethod.LDAP, hvac.exceptions.InvalidRequest(), VaultAuthenticationError),
            # General exception
            (Environment.DEV, AuthMethod.IAM, Exception("Unexpected Error"), VaultAuthenticationError),
            (Environment.QA, AuthMethod.IAM, Exception("Unexpected Error"), VaultAuthenticationError),
            (Environment.PROD, AuthMethod.IAM, Exception("Unexpected Error"), VaultAuthenticationError),            
        ],
        ids=[
            "InvalidRequest_DEV",
            "InvalidRequest_QA",
            "InvalidRequest_PROD",                        
            "Unauthorized_DEV",
            "Unauthorized_QA",
            "Unauthorized_PROD",            
            "ConnectionError_DEV",
            "ConnectionError_QA",
            "ConnectionError_PROD",                        
            "Timeout_DEV",
            "Timeout_QA",
            "Timeout_PROD",            
            "InvalidURL_DEV",
            "InvalidURL_QA",
            "InvalidURL_PROD",                                             
            "InvalidToken_DEV",
            "InvalidToken_QA",
            "InvalidToken_PROD",
            "InvalidCredentials_LDAP",
            "UnexpectedError_DEV",
            "UnexpectedError_QA",
            "UnexpectedError_PROD",            
        ]
    )
    def test_authenticate_failure(
        self, 
        mock_client,
        mock_logger,
        reset_secret_store_instance,
        side_effect,
        expected_exception
    ):
        # Set up the mock client if a side effect is specified
        if side_effect:
            if self.auth_method == AuthMethod.LDAP:
                mock_client.auth.ldap.login.side_effect = side_effect
            else:  # Assuming IAM auth uses token authentication
                mock_client.auth.token.lookup.side_effect = side_effect 
            mock_client.is_authenticated.return_value = False
        
        # Attempt authentication and expect the corresponding exception
        with pytest.raises(expected_exception):
            SecretStore(
                environment=self.environment, auth_method=self.auth_method
            )

        # Check that the logger was called with an error message 
        mock_logger.error.assert_called()