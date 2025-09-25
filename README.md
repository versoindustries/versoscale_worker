# VersoScale Worker

The VersoScale Worker is a robust, secure, and resilient client for participating in large-scale distributed machine learning tasks. It is designed to connect to the VersoScale ecosystem, securely authenticate, and process training jobs dispatched by a central coordinator.

This worker is built with **security** and **resilience** as first principles, utilizing mutual TLS (mTLS) for all communications and implementing sophisticated resilience patterns like automatic retries, exponential backoff, and a circuit breaker to handle unreliable network conditions.

## ✨ Key Features

- **🔒 Secure by Design**: All gRPC communication with the coordinator and parameter server is secured using mutual TLS (mTLS), ensuring both client and server authentication and encrypted traffic.
- **🔄 Resilient Communication**: A built-in gRPC interceptor provides:
  - **Automatic Retries**: Transparently retries failed operations due to transient network errors.
  - **Exponential Backoff & Jitter**: Intelligently spaces out retries to avoid overwhelming a recovering server.
  - **Circuit Breaker**: Prevents repeated calls to a failing service, allowing recovery time.
- **🏢 Multi-Tenant Architecture**: Authenticates via tenant-specific API keys for a multi-tenant system.
- **🚀 Simplified Onboarding**: One-step command-line process to create a tenant and generate an admin API key.
- **📊 Web-based Monitoring UI**: Each worker instance launches a local Flask web server with a real-time dashboard for status, logs, and control.

## ⚙️ How It Works

The VersoScale Worker consists of two primary components:

1. **Runner (`runner.py`)**: The main entry point. It handles initial authentication by exchanging a long-lived API Key for a short-lived, single-use Registration Token from the Tenant Management Service.
2. **Client (`client.py`)**: Launched by the runner, it uses the token for one-time registration with the Coordinator via a secure HTTPS endpoint. It submits a Certificate Signing Request (CSR) and receives a unique mTLS client certificate for subsequent gRPC communication. The certificate is automatically renewed before expiration.

Once registered, the worker polls the Coordinator for tasks (e.g., HPO trials or training shards), syncs model weights with the Parameter Server, and reports progress.

## 🏁 Getting Started

### Prerequisites

- Python 3.8 or higher.
- Access to a running VersoScale services stack (Coordinator, Parameter Server, Tenant Management).

### Installation

Clone the repository and install dependencies:

```bash
# Clone the repository
git clone https://github.com/example/versoscale-worker.git
cd versoscale-worker

# Install the package and its dependencies
pip install .
```

### Usage

The `runner.py` script is the entry point for all operations.

#### Step 1: First-Time Setup (Onboarding)

For new users without an API key, create a tenant and generate an admin API key:

```bash
python versoscale_worker/runner.py --onboard "My New Company"
```

**Expected Output**:

```
==================================================
🎉 Onboarding Successful! 🎉
  Tenant Name: My New Company
  Tenant ID:   ten-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
--------------------------------------------------
Your new admin API key is listed below.
Please save it in a secure location. You will not be shown it again.
--------------------------------------------------

vsk_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

==================================================

To start your first worker, run:
python versoscale_worker/runner.py --api-key vsk_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

**Important**: Save the API key securely (e.g., in a password manager). It will not be shown again.

#### Step 2: Running a Worker

Start a worker using your API key in one of two ways:

**Option 1: Command-Line Argument (Recommended for testing)**

```bash
python versoscale_worker/runner.py --api-key <YOUR_SAVED_API_KEY>
```

**Option 2: Environment Variable (Recommended for production/scripts)**

Linux/macOS:

```bash
export VERSOSCALE_API_KEY=<YOUR_SAVED_API_KEY>
python versoscale_worker/runner.py
```

Windows (Command Prompt):

```bash
set VERSOSCALE_API_KEY=<YOUR_SAVED_API_KEY>
python versoscale_worker/runner.py
```

The worker will register and begin polling for jobs.

### 🖥️ Monitoring via Web UI

Upon starting, the worker launches a local web-based UI at:

```
http://127.0.0.1:5000
```

The UI provides:

- **Real-time Status**: View the worker's state (e.g., Initializing, Connected, Training, Idle).
- **Live Log Stream**: See logs as they happen.
- **Worker Details**: View Worker ID and mTLS certificate expiration.
- **Playback Controls**: Pause or resume job processing.

## 🗺️ Roadmap

- **[In Progress] Public Domain & Network Configuration**: Enable public-facing domains for gRPC services and update worker to connect to non-localhost addresses.
- **[Planned] Public Worker Pools**: Allow workers from the public internet to join the compute network securely.

## 🤝 Contributing

Contributions are welcome! Submit pull requests or open issues for bugs, feature requests, or suggestions.

## 📄 License

This project is licensed under the MIT License. See the `LICENSE` file for details.