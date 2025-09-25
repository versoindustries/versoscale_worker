import argparse
import grpc
import os
import sys
import uuid
from pathlib import Path
from datetime import datetime, timezone, timedelta

# Import the main client module to be launched
try:
    from versoscale_worker import client
except ImportError:
    class MockClient:
        def launch(self, token):
            print(f"[Mock Client] Launched with token prefix: {token[:8]}...")
            print("[Mock Client] Worker is now running.")
    client = MockClient()


from google.protobuf import timestamp_pb2
try:
    from .protos import tenant_management_pb2
    from .protos import tenant_management_pb2_grpc
except ImportError:
    print("[Runner] CRITICAL: Could not import protobuf modules.")
    print("           Please ensure that the 'protos' directory is in the same directory as this script,")
    print("           or that the compiled protobufs are available on your PYTHONPATH.")
    sys.exit(1)


# --- Constants ---
TENANT_SERVICE_ADDRESS = 'localhost:50052'
# --- FIX: Certificate paths are now relative to this script's location ---
SCRIPT_DIR = Path(__file__).parent
CA_CERT_PATH = SCRIPT_DIR / "ca-cert.pem"
CLIENT_KEY_PATH = SCRIPT_DIR / "client-key.pem"
CLIENT_CERT_PATH = SCRIPT_DIR / "client-cert.pem"


def onboard_new_tenant(tenant_name: str):
    """
    Calls the unauthenticated onboarding endpoint to create a new tenant
    and retrieve the first API key.
    """
    print(f"[Runner] Starting onboarding for new tenant: '{tenant_name}'...")

    # --- Use a secure channel for onboarding ---
    try:
        ca_cert = CA_CERT_PATH.read_bytes()
        credentials = grpc.ssl_channel_credentials(root_certificates=ca_cert)
        channel = grpc.secure_channel(TENANT_SERVICE_ADDRESS, credentials)
    except FileNotFoundError:
        abs_path = os.path.abspath(SCRIPT_DIR)
        print(f"\n[Runner] CRITICAL: Onboarding failed.")
        print(f"           Could not find the Certificate Authority file 'ca-cert.pem'.")
        print(f"           The script is looking for it in this directory:")
        print(f"           > {abs_path}")
        print(f"           Please ensure 'ca-cert.pem' from the 'client_certs' directory is copied here.")
        return

    try:
        stub = tenant_management_pb2_grpc.TenantManagementServiceStub(channel)
        request = tenant_management_pb2.OnboardNewTenantRequest(name=tenant_name)
        response = stub.OnboardNewTenant(request)

        print("\n" + ("=" * 50))
        print("🎉 Onboarding Successful! 🎉")
        print(f"  Tenant Name: {response.tenant.name}")
        print(f"  Tenant ID:   {response.tenant.tenant_id}")
        print("\n" + ("-" * 50))
        print("Your new admin API key is listed below. ")
        print("Please save it in a secure location. You will not be shown it again.")
        print("-" * 50)
        print(f"\n{response.admin_api_key}\n")
        print("=" * 50)
        print("\nTo start your first worker, run the following command:")
        print(f"python {sys.argv[0]} --api-key {response.admin_api_key}\n")

    except grpc.RpcError as e:
        print(f"\n[Runner] CRITICAL: Onboarding failed.")
        print(f"           Could not connect to the VersoScale service at {TENANT_SERVICE_ADDRESS}.")
        details = e.details()
        if e.code() == grpc.StatusCode.UNAVAILABLE and 'Ssl handshake failed' in details:
            print(f"           SSL Handshake Error: The server's security certificate could not be verified.")
            print(f"           Please ensure the server at {TENANT_SERVICE_ADDRESS} is using a certificate signed")
            print(f"           by the correct Certificate Authority (the one in '{CA_CERT_PATH.name}').")
            if "certificate signature failure" in details:
                print(f"           Details: The certificate signature is invalid, which confirms a mismatch between your certs.")
        else:
            print(f"           gRPC Error: {details}")
        sys.exit(1)
    finally:
        if 'channel' in locals():
            channel.close()


def get_registration_token(api_key: str) -> str:
    """
    Contacts the Tenant Management service to exchange a persistent API key for a
    short-lived worker registration token.
    """
    print(f"[Runner] Getting registration token using API key prefix: {api_key[:8]}...")

    # --- START FIX: Use the same credentials as onboarding, without a client cert ---
    try:
        ca_cert = CA_CERT_PATH.read_bytes()
        credentials = grpc.ssl_channel_credentials(root_certificates=ca_cert)
        channel = grpc.secure_channel(TENANT_SERVICE_ADDRESS, credentials)
    except FileNotFoundError as fe:
        abs_path = os.path.abspath(SCRIPT_DIR)
        print(f"\n[Runner] CRITICAL: Failed to get registration token.")
        print(f"           Could not find required certificate file: {fe.filename}")
        print(f"           The script is looking for your certificate files in this directory:")
        print(f"           > {abs_path}")
        print(f"\n           Please ensure 'ca-cert.pem' is present.")
        sys.exit(1)
    # --- END FIX ---

    try:
        metadata = [('x-api-key', api_key)]
        stub = tenant_management_pb2_grpc.TenantManagementServiceStub(channel)

        expiration_ts = timestamp_pb2.Timestamp()
        expiration_ts.FromDatetime(datetime.now(timezone.utc) + timedelta(minutes=5))

        request_msg = tenant_management_pb2.CreateApiKeyRequest(
            name=f"worker-reg-token-{uuid.uuid4().hex[:8]}",
            expiration_time=expiration_ts
        )

        response = stub.CreateApiKey(request=request_msg, metadata=metadata)
        token = response.secret_key

        if not token:
            raise ValueError("Received an empty token from the server.")

        print("[Runner] Successfully received one-time registration token.")
        return token
    except grpc.RpcError as e:
        print(f"[Runner] CRITICAL: Failed to get registration token.")
        if e.code() == grpc.StatusCode.UNAUTHENTICATED:
            print("           The API key provided is invalid or expired.")
        else:
            details = e.details()
            print(f"           Server may be down. gRPC Error: {details}")
            # Add specific check for the SSL handshake error to provide a better message
            if e.code() == grpc.StatusCode.UNAVAILABLE and 'Ssl handshake failed' in details:
                 print(f"           SSL Handshake Error: The server's security certificate could not be verified.")
                 print(f"           Please ensure the server at {TENANT_SERVICE_ADDRESS} is using a certificate signed")
                 print(f"           by the correct Certificate Authority (the one in '{CA_CERT_PATH.name}').")
                 if "certificate signature failure" in details:
                     print(f"           Details: The certificate signature is invalid, which confirms a mismatch between your certs.")
        sys.exit(1)
    finally:
        if 'channel' in locals():
            channel.close()


def main():
    """
    Main entry point for the Worker. Handles argument parsing for both
    onboarding and normal worker execution.
    """
    parser = argparse.ArgumentParser(
        description="VersoScale Worker Launcher. Use --onboard for first-time setup."
    )

    parser.add_argument(
        '--onboard',
        type=str,
        metavar='"TENANT NAME"',
        help="Onboard a new tenant and generate the first API key. "
             "If used, all other arguments are ignored."
    )

    parser.add_argument(
        '--api-key',
        type=str,
        help="The tenant API key for authenticating to the VersoScale platform."
    )

    args = parser.parse_args()

    if args.onboard:
        onboard_new_tenant(args.onboard)
        sys.exit(0)

    api_key = args.api_key or os.environ.get("VERSOSCALE_API_KEY")

    if not api_key:
        print("[Runner] CRITICAL: No API key provided.")
        print("Please use the --api-key argument or set the VERSOSCALE_API_KEY environment variable.")
        print(f"If this is your first time, use: python {sys.argv[0]} --onboard \"Your Company Name\"")
        sys.exit(1)

    registration_token = get_registration_token(api_key)

    print("-" * 40)
    print("[Runner] Handing off to the main worker client...")
    print("-" * 40)

    client.launch(registration_token)


if __name__ == "__main__":
    main()
