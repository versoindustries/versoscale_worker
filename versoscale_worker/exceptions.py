"""
Custom exceptions for the VersoScale worker client.

This module defines a set of custom exceptions to allow for more specific
error handling and clearer, more expressive code when dealing with issues
that may arise during the distributed training lifecycle. All custom
exceptions inherit from the base VersoScaleError.
"""

class VersoScaleError(Exception):
    """Base exception for all custom errors in the VersoScale worker package."""
    pass

class NetworkError(VersoScaleError):
    """
    Raised when there is a fundamental network issue, such as an inability
    to connect to a server endpoint. This often wraps a gRPC RpcError.
    """
    def __init__(self, message, original_error=None):
        super().__init__(message)
        self.original_error = original_error

class AuthenticationError(VersoScaleError):
    """
    Raised when the worker fails to authenticate with the Coordinator.
    This could be due to an invalid, expired, or already used bootstrap token.
    """
    pass

class RegistrationError(VersoScaleError):
    """
    Raised for failures during the worker registration process that are not
    specifically authentication-related, such as failing to get a certificate
    signed after a successful authentication.
    """
    pass

class CertificateError(VersoScaleError):
    """
    Raised for failures related to certificate management, such as loading,
    parsing, or failed renewal attempts.
    """
    pass

class DataIntegrityError(VersoScaleError):
    """
    Raised when the hash of received data does not match the expected hash,
    indicating potential corruption or a man-in-the-middle attack.
    """
    pass

class TaskRequestError(VersoScaleError):
    """
    Raised when a worker fails to request or receive a data shard from the
    Coordinator after being successfully registered and connected.
    """
    pass

class ParameterSyncError(VersoScaleError):
    """
    Raised when there's an error communicating with the Parameter Server,
    either when pushing gradients or pulling parameters.
    """
    pass

class ModelConfigurationError(VersoScaleError):
    """
    Raised if the local model's architecture is incompatible with the
    parameters received from the Parameter Server.
    """
    pass

class ServerUnresponsiveError(VersoScaleError):
    """
    Raised by the resilience layer when a server is consistently failing,
    and the circuit breaker has opened.
    """
    pass
