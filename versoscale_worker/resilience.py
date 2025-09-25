"""
A client-side resilience layer for VersoScale gRPC communication.

This module provides a gRPC client interceptor that transparently adds
robustness to all outgoing RPC calls. It implements several critical
resilience patterns necessary for operating over unreliable networks like
the public internet.

Key Features:
- Timeouts: Enforces a deadline on all RPCs to prevent indefinite hanging.
- Retries: Automatically retries failed RPCs due to transient network or
  server errors.
- Exponential Backoff & Jitter: Intelligently spaces out retry attempts to
  avoid overwhelming a recovering server.
- Circuit Breaker: Prevents the client from repeatedly calling a service
  that is consistently failing, allowing the service time to recover.
"""

import time
import random
import grpc
import threading
from typing import Callable, Any
from collections import namedtuple

# Import custom exceptions for more specific error handling
from versoscale_worker.exceptions import NetworkError, ServerUnresponsiveError

# --- Default Configuration ---
DEFAULT_TIMEOUT_SECONDS = 15.0
DEFAULT_MAX_RETRIES = 3
DEFAULT_INITIAL_BACKOFF_MS = 100
DEFAULT_MAX_BACKOFF_MS = 1000
DEFAULT_BACKOFF_MULTIPLIER = 2.0
DEFAULT_CIRCUIT_BREAKER_FAILURES = 5
DEFAULT_CIRCUIT_BREAKER_RESET_SEC = 30

# A set of gRPC status codes that are considered safe to retry.
# These typically indicate a transient network or temporary server issue.
RETRYABLE_STATUS_CODES = {
    grpc.StatusCode.UNAVAILABLE,
    grpc.StatusCode.DEADLINE_EXCEEDED,
    grpc.StatusCode.RESOURCE_EXHAUSTED,
}

class CircuitBreaker:
    """
    Implements the Circuit Breaker pattern.

    After a certain number of consecutive failures, the circuit "opens" and
    all subsequent calls will fail immediately for a configured cooldown period.
    After the cooldown, it enters a "half-open" state, allowing one test call.
    If the test call succeeds, the circuit closes; otherwise, it opens again.
    """
    STATE_CLOSED = "CLOSED"
    STATE_OPEN = "OPEN"
    STATE_HALF_OPEN = "HALF_OPEN"

    def __init__(
        self,
        failure_threshold: int = DEFAULT_CIRCUIT_BREAKER_FAILURES,
        reset_timeout: int = DEFAULT_CIRCUIT_BREAKER_RESET_SEC,
    ):
        self.failure_threshold = failure_threshold
        self.reset_timeout = reset_timeout
        self._state = self.STATE_CLOSED
        self._failure_count = 0
        self._last_failure_time = 0
        self._lock = threading.Lock()

    @property
    def state(self):
        with self._lock:
            if self._state == self.STATE_OPEN and self._is_timeout_expired():
                self._state = self.STATE_HALF_OPEN
            return self._state

    def _is_timeout_expired(self) -> bool:
        return time.monotonic() - self._last_failure_time > self.reset_timeout

    def record_failure(self):
        with self._lock:
            self._failure_count += 1
            if self._failure_count >= self.failure_threshold:
                self._state = self.STATE_OPEN
                self._last_failure_time = time.monotonic()

    def record_success(self):
        with self._lock:
            self._failure_count = 0
            self._state = self.STATE_CLOSED


class ResilienceInterceptor(
    grpc.UnaryUnaryClientInterceptor,
    grpc.UnaryStreamClientInterceptor,
    grpc.StreamUnaryClientInterceptor,
    grpc.StreamStreamClientInterceptor
):
    """
    gRPC interceptor that provides timeouts, retries, and circuit breaking.
    """
    _ClientCallDetails = namedtuple(
    '_ClientCallDetails',
    ('method', 'timeout', 'metadata', 'credentials', 'wait_for_ready'))

    def __init__(
        self,
        max_retries: int = DEFAULT_MAX_RETRIES,
        initial_backoff_ms: int = DEFAULT_INITIAL_BACKOFF_MS,
        max_backoff_ms: int = DEFAULT_MAX_BACKOFF_MS,
        backoff_multiplier: float = DEFAULT_BACKOFF_MULTIPLIER,
    ):
        self.max_retries = max_retries
        self.initial_backoff_ms = initial_backoff_ms
        self.max_backoff_ms = max_backoff_ms
        self.backoff_multiplier = backoff_multiplier
        # Each service endpoint gets its own circuit breaker instance
        self.circuit_breakers = {}
        self._cb_lock = threading.Lock()

    def _get_circuit_breaker(self, method: str) -> CircuitBreaker:
        """Lazily creates a CircuitBreaker for a given gRPC method."""
        with self._cb_lock:
            if method not in self.circuit_breakers:
                self.circuit_breakers[method] = CircuitBreaker()
            return self.circuit_breakers[method]

    def _intercept_call(
        self,
        continuation: Callable,
        client_call_details: grpc.ClientCallDetails,
        request: Any,
        is_stream: bool
    ) -> Any:
        """Core logic for retrying a gRPC call."""
        method = client_call_details.method
        circuit_breaker = self._get_circuit_breaker(method)
        current_backoff_ms = self.initial_backoff_ms
        last_exception = None

        for attempt in range(self.max_retries + 1):
            # 1. Check Circuit Breaker state
            cb_state = circuit_breaker.state
            if cb_state == CircuitBreaker.STATE_OPEN:
                raise ServerUnresponsiveError(
                    f"Circuit breaker is open for method {method}. Not attempting call."
                )

            try:
                # 2. Add timeout to the call details
                if client_call_details.timeout is None:
                    details_with_timeout = self._ClientCallDetails(
                        method=client_call_details.method,
                        timeout=DEFAULT_TIMEOUT_SECONDS,
                        metadata=client_call_details.metadata,
                        credentials=client_call_details.credentials,
                        wait_for_ready=client_call_details.wait_for_ready
                    )
                else:
                    details_with_timeout = client_call_details
                
                # 3. Make the actual RPC call
                response = continuation(details_with_timeout, request)
                
                # If the call is a streaming response, we must iterate to trigger potential errors
                if is_stream:
                    # This consumes the iterator, so it's only for error checking
                    # A more robust implementation might wrap the iterator.
                    try:
                        list(response)
                        # Re-create the iterator by calling continuation again
                        response = continuation(details_with_timeout, request)
                    except grpc.RpcError as e:
                        # Catch errors that occur during iteration
                        raise e


                # 4. Record success if the call completes without a gRPC error
                circuit_breaker.record_success()
                return response

            except grpc.RpcError as e:
                last_exception = e
                # 5. Check if the error is retryable
                if e.code() in RETRYABLE_STATUS_CODES:
                    circuit_breaker.record_failure()
                    
                    # Last attempt shouldn't sleep
                    if attempt < self.max_retries:
                        # Calculate sleep time with jitter
                        jitter_ms = random.randint(0, int(current_backoff_ms * 0.1))
                        sleep_duration_sec = (current_backoff_ms + jitter_ms) / 1000.0
                        time.sleep(sleep_duration_sec)
                        
                        # Increase backoff for next attempt
                        current_backoff_ms = min(
                            current_backoff_ms * self.backoff_multiplier,
                            self.max_backoff_ms
                        )
                    continue
                else:
                    # Non-retryable gRPC error, fail fast
                    circuit_breaker.record_failure()
                    raise NetworkError(f"Non-retryable gRPC error for {method}: {e.details()}", original_error=e) from e
        
        # If we exit the loop, it means all retries failed
        raise NetworkError(
            f"RPC call to {method} failed after {self.max_retries + 1} attempts.",
            original_error=last_exception
        ) from last_exception

    def intercept_unary_unary(
        self,
        continuation: Callable[[grpc.ClientCallDetails, Any], grpc.Call],
        client_call_details: grpc.ClientCallDetails,
        request: Any,
    ) -> grpc.Call:
        return self._intercept_call(continuation, client_call_details, request, is_stream=False)
    
    def intercept_unary_stream(
        self,
        continuation: Callable[[grpc.ClientCallDetails, Any], grpc.Call],
        client_call_details: grpc.ClientCallDetails,
        request: Any,
    ) -> grpc.Call:
        return self._intercept_call(continuation, client_call_details, request, is_stream=True)

    def intercept_stream_unary(
        self,
        continuation: Callable[[grpc.ClientCallDetails, Any], grpc.Call],
        client_call_details: grpc.ClientCallDetails,
        request_iterator: Any,
    ) -> grpc.Call:
        # Note: Retrying stream-request RPCs is complex as the iterator may be partially consumed.
        # For now, we apply the circuit breaker but do not retry.
        circuit_breaker = self._get_circuit_breaker(client_call_details.method)
        if circuit_breaker.state == CircuitBreaker.STATE_OPEN:
            raise ServerUnresponsiveError(
                f"Circuit breaker is open for {client_call_details.method}. Not attempting call."
            )
        try:
            result = continuation(client_call_details, request_iterator)
            circuit_breaker.record_success()
            return result
        except grpc.RpcError as e:
            circuit_breaker.record_failure()
            raise NetworkError(f"gRPC error for {client_call_details.method}: {e.details()}", original_error=e) from e

    def intercept_stream_stream(
        self,
        continuation: Callable[[grpc.ClientCallDetails, Any], grpc.Call],
        client_call_details: grpc.ClientCallDetails,
        request_iterator: Any,
    ) -> grpc.Call:
        # Streaming in both directions is not retried for the same reasons as stream_unary.
        circuit_breaker = self._get_circuit_breaker(client_call_details.method)
        if circuit_breaker.state == CircuitBreaker.STATE_OPEN:
            raise ServerUnresponsiveError(
                f"Circuit breaker is open for {client_call_details.method}. Not attempting call."
            )
        try:
            result = continuation(client_call_details, request_iterator)
            circuit_breaker.record_success()
            return result
        except grpc.RpcError as e:
            circuit_breaker.record_failure()
            raise NetworkError(f"gRPC error for {client_call_details.method}: {e.details()}", original_error=e) from e