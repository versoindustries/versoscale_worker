import grpc
import time
import os
import ssl
import threading
import queue
import random
import json
import requests
from pathlib import Path
import tensorflow as tf
from flask import Flask, jsonify, request, Response
import hashlib
from datetime import datetime, timedelta, timezone

# --- Cryptography Imports for Certificate Management ---
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Import the generated gRPC modules
from .protos import coordinator_pb2, coordinator_pb2_grpc, parameter_server_pb2, parameter_server_pb2_grpc

# Import local modules for resilience and updated error handling
from versoscale_worker.resilience import ResilienceInterceptor
from versoscale_worker.exceptions import (
    AuthenticationError,
    RegistrationError,
    CertificateError,
    DataIntegrityError,
    NetworkError,
    ServerUnresponsiveError,
    VersoScaleError,
)

# --- Constants ---
# --- START FIX: Corrected gRPC port and updated HTTPS port ---
COORDINATOR_GRPC_ADDRESS = 'localhost:50050'  # The main gRPC port for the Coordinator
COORDINATOR_HTTPS_ADDRESS = 'https://localhost:8443' # The registration REST endpoint for the Coordinator
# --- END FIX ---
PARAMETER_SERVER_ADDRESS = 'localhost:50051'
CERT_DIR = Path("./worker_certs")
HEARTBEAT_INTERVAL_SEC = 45
CERT_RENEWAL_THRESHOLD_HOURS = 24

class AuthManager:
    """
    Manages client-side authentication, including key generation, CSR creation,
    and certificate lifecycle checks.
    """

    def __init__(self, cert_dir: Path):
        self.cert_dir = cert_dir
        self.cert_dir.mkdir(exist_ok=True)
        self.ca_cert_path = self.cert_dir / "ca-cert.pem"
        self.worker_key_path = self.cert_dir / "worker-key.pem"
        self.worker_cert_path = self.cert_dir / "worker-cert.pem"

    def credentials_exist(self) -> bool:
        """Check if the worker's key and certificate already exist."""
        return self.worker_key_path.exists() and self.worker_cert_path.exists()

    def generate_key_and_csr(self, worker_id: str = "pending-registration") -> tuple[rsa.RSAPrivateKey, str]:
        """
        Generates a new 2048-bit RSA private key and a PEM-encoded CSR.
        Returns the private key object and the CSR as a string.
        """
        print(f"[AuthManager] Generating 2048-bit RSA key and CSR for CN='{worker_id}'...")
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "VersoScale Workers"),
            x509.NameAttribute(NameOID.COMMON_NAME, worker_id),
        ])

        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(subject)
            .sign(private_key, hashes.SHA256())
        )
        csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        print("[AuthManager] Key and CSR generated successfully.")
        return private_key, csr_pem

    def save_credentials(self, private_key: rsa.RSAPrivateKey, worker_cert: bytes, ca_cert: bytes):
        """Saves the worker's private key, certificate, and the CA cert."""
        print("[AuthManager] Saving worker key, worker certificate, and CA certificate...")
        with open(self.worker_key_path, "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
        with open(self.worker_cert_path, "wb") as f:
            f.write(worker_cert)
        
        with open(self.ca_cert_path, "wb") as f:
            f.write(ca_cert)

    def load_ssl_channel_credentials(self) -> grpc.ChannelCredentials:
        """Loads all credentials from disk required for a secure mTLS channel."""
        try:
            if not self.credentials_exist() or not self.ca_cert_path.exists():
                raise CertificateError("mTLS credentials not found on disk. Cannot create secure channel.")
            
            private_key = self.worker_key_path.read_bytes()
            certificate_chain = self.worker_cert_path.read_bytes()
            root_certificates = self.ca_cert_path.read_bytes()
            
            return grpc.ssl_channel_credentials(
                root_certificates=root_certificates,
                private_key=private_key,
                certificate_chain=certificate_chain
            )
        except (IOError, ValueError) as e:
            raise CertificateError(f"Failed to load SSL credentials from disk: {e}") from e

    def get_certificate(self) -> x509.Certificate | None:
        """Loads and parses the worker's X.509 certificate from disk."""
        if not self.worker_cert_path.exists():
            return None
        try:
            cert_bytes = self.worker_cert_path.read_bytes()
            return x509.load_pem_x509_certificate(cert_bytes)
        except (IOError, ValueError) as e:
            raise CertificateError(f"Error loading or parsing certificate: {e}") from e

    def get_worker_id_from_cert(self) -> str | None:
        """Extracts the Common Name (CN) from the certificate, which serves as the worker_id."""
        cert = self.get_certificate()
        if cert:
            try:
                return cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            except (IndexError, AttributeError):
                return None
        return None

    def is_certificate_nearing_expiry(self, threshold_hours: int) -> bool:
        """Checks if the certificate will expire within the given threshold."""
        cert = self.get_certificate()
        if not cert:
            return True # If no cert, it's effectively expired and needs replacement.
        
        time_to_expiry = cert.not_valid_after_utc - datetime.now(timezone.utc)
        return time_to_expiry < timedelta(hours=threshold_hours)

class TrainingWorker(threading.Thread):
    """
    Handles the core logic of connecting, communicating with servers, and executing
    work dispatched by the Coordinator.
    """
    def __init__(self, coordinator_grpc_addr, coordinator_https_addr, ps_addr, registration_token, log_queue, status_queue):
        super().__init__(daemon=True)
        self.worker_id = "Unregistered"
        self.cert_expiry = "N/A"
        self.log_queue = log_queue
        self.status_queue = status_queue
        
        self.coordinator_grpc_addr = coordinator_grpc_addr
        self.coordinator_https_addr = coordinator_https_addr
        self.ps_addr = ps_addr
        self.registration_token = registration_token
        
        self.auth_manager = AuthManager(CERT_DIR)
        self.model = self._initialize_model()
        
        self._paused = threading.Event()
        self._stop_event = threading.Event()

    def _log(self, message: str, status: str = None):
        self.log_queue.put(message)
        if status:
            self.status_queue.put({
                "status": status,
                "worker_id": self.worker_id,
                "cert_expiry": self.cert_expiry
            })

    def _initialize_model(self):
        inputs = tf.keras.Input(shape=(10,))
        outputs = tf.keras.layers.Dense(1)(inputs)
        return tf.keras.Model(inputs=inputs, outputs=outputs)

    def run(self):
        self._log("--- Starting VersoScale Worker ---", "Initializing")
        try:
            self._manage_certificate_lifecycle()

            resilience_interceptor = ResilienceInterceptor()
            secure_creds = self.auth_manager.load_ssl_channel_credentials()
            
            coord_channel = grpc.intercept_channel(grpc.secure_channel(self.coordinator_grpc_addr, secure_creds), resilience_interceptor)
            ps_channel = grpc.intercept_channel(grpc.secure_channel(self.ps_addr, secure_creds), resilience_interceptor)

            self.coordinator_stub = coordinator_pb2_grpc.CoordinatorServiceStub(coord_channel)
            self.ps_stub = parameter_server_pb2_grpc.ParameterServerServiceStub(ps_channel)
            
            self._log(f"Secure mTLS channels established for worker '{self.worker_id}'.", "Connected")
            self._start_heartbeat()
            self._run_work_loop()

        except VersoScaleError as e:
            self._log(f"A critical worker error occurred: {e}", "ERROR")
        except Exception as e:
            self._log(f"An unexpected fatal error occurred: {e}", "FATAL ERROR")
        finally:
            self._log("--- Worker Thread Stopped ---", "Stopped")
            if 'coord_channel' in locals(): coord_channel.close()
            if 'ps_channel' in locals(): ps_channel.close()

    def _manage_certificate_lifecycle(self):
        """Handles initial registration or renewal based on credential status."""
        if not self.auth_manager.credentials_exist() or self.auth_manager.is_certificate_nearing_expiry(CERT_RENEWAL_THRESHOLD_HOURS):
            if not self.auth_manager.credentials_exist():
                self._log("No credentials found. Starting first-time registration.", "Registering")
            else:
                self._log("Certificate is nearing expiry. Attempting renewal.", "Renewing Cert")
            
            if not self.registration_token:
                raise AuthenticationError("A registration token is required. The runner script should provide one.")
            
            self._register_with_coordinator_https()
        else:
            self._log("Existing credentials found. Verifying identity.", "Authenticating")
            self.worker_id = self.auth_manager.get_worker_id_from_cert()
            cert = self.auth_manager.get_certificate()
            if cert:
                self.cert_expiry = cert.not_valid_after_utc.strftime('%Y-%m-%d %H:%M:%S UTC')
            self._log(f"Certificate is valid. Expires: {self.cert_expiry}", "Authenticated")
        
        if self.worker_id is None or self.worker_id == "Unregistered":
             raise CertificateError("Could not determine worker ID from certificate after lifecycle management.")

    def _register_with_coordinator_https(self):
        """
        Handles first-time registration or renewal via a one-time HTTPS POST.
        """
        self._log("Generating new key and CSR for HTTPS registration.", "Registering")
        private_key, csr_pem = self.auth_manager.generate_key_and_csr()
        
        registration_url = f"{self.coordinator_https_addr}/v1/register"

        # --- START FIX: Align JSON payload with coordinator expectations ---
        # The coordinator's /v1/register endpoint expects a JSON object with
        # 'registration_token' and 'csr' keys. This corrects the payload format.
        payload = {
            "registration_token": self.registration_token,
            "csr": csr_pem
        }
        # --- END FIX ---
        
        self._log(f"Sending CSR to HTTPS endpoint: {registration_url}", "Registering")
        try:
            # For local testing with self-signed certs, `verify` can be set to False.
            # In production, this should be True or the path to the CA bundle.
            response = requests.post(registration_url, json=payload, timeout=30, verify=False)
            response.raise_for_status() 

            data = response.json()
            
            if not all(k in data for k in ['worker_id', 'certificate', 'ca_certificate']):
                raise RegistrationError("HTTPS registration response was missing required fields.")

            self.worker_id = data['worker_id']
            worker_cert_bytes = data['certificate'].encode('utf-8')
            ca_cert_bytes = data['ca_certificate'].encode('utf-8')

            self.auth_manager.save_credentials(private_key, worker_cert_bytes, ca_cert_bytes)
            
            cert = self.auth_manager.get_certificate()
            self.cert_expiry = cert.not_valid_after_utc.strftime('%Y-%m-%d %H:%M:%S UTC')
            self._log(f"Registration/Renewal successful! Worker ID: {self.worker_id}", "Registered")

        except requests.exceptions.HTTPError as e:
            if e.response.status_code in [401, 403]:
                raise AuthenticationError(f"Registration token is invalid or expired. Server responded with {e.response.status_code}.") from e
            else:
                raise RegistrationError(f"HTTP error during registration: {e}") from e
        except requests.exceptions.RequestException as e:
            raise NetworkError(f"Network error during HTTPS registration: {e}") from e
        except Exception as e:
            raise RegistrationError(f"An unexpected error occurred during HTTPS registration: {e}") from e

    def _run_work_loop(self):
        """The main loop for requesting and executing any work from the Coordinator."""
        while not self._stop_event.is_set():
            self._paused.wait()
            try:
                self._log("Requesting next available work...", "Requesting Work")
                work_response = self.coordinator_stub.RequestWork(coordinator_pb2.WorkRequest())
                
                task_type = work_response.WhichOneof('task')

                if task_type == 'hpo_trial':
                    self._handle_hpo_trial(work_response.hpo_trial)
                elif task_type == 'training_shard':
                    self._handle_training_shard(work_response.training_shard)
                else:
                    self._log("No tasks available from Coordinator. Waiting.", "Idle")
                    self._stop_event.wait(30)
                    
            except DataIntegrityError:
                self._log("Data integrity error. Skipping shard and requesting next task.", "Warning")
                pass
            except ServerUnresponsiveError as e:
                self._log(f"Server is unresponsive: {e}. Waiting for recovery...", "Connection Lost")
                self._stop_event.wait(60)
            except NetworkError as e:
                self._log(f"Transient network error in work loop: {e}", "Connection Issue")
                self._stop_event.wait(20)
            except VersoScaleError as e:
                self._log(f"A recoverable error occurred in work loop: {e}", "ERROR")
                self._stop_event.wait(30)

    def _handle_training_shard(self, shard_info):
        """Processes a single model training data shard."""
        self._log(f"Received training shard {shard_info.shard_id} for job {shard_info.job_id}.", "Verifying")
        
        expected_hash = shard_info.shard_hash
        calculated_hash = hashlib.sha256(shard_info.url.encode('utf-8')).hexdigest()

        if expected_hash != calculated_hash:
            error_msg = f"Hash mismatch for shard {shard_info.shard_id}. Expected {expected_hash}, got {calculated_hash}"
            self._log(f"CRITICAL: {error_msg}", "ERROR")
            raise DataIntegrityError(error_msg)
        
        self._log("Shard integrity verified. Starting training cycle.", "Training")
        self._pull_parameters()
        
        self._log("Simulating training and computing gradients...", "Computing")
        time.sleep(2)
        dummy_gradients = [tf.random.normal(v.shape) for v in self.model.trainable_variables]
        
        self._push_gradients(dummy_gradients)
        
        self._log(f"Reporting shard completion for {shard_info.shard_id}.", "Reporting")
        completion_req = coordinator_pb2.ShardCompletionRequest(
            job_id=shard_info.job_id,
            shard_id=shard_info.shard_id,
            results_json=json.dumps({"accuracy": round(random.uniform(0.9, 0.98), 4)})
        )
        self.coordinator_stub.MarkShardComplete(completion_req)
        self._log(f"Shard {shard_info.shard_id} completed.", "Idle")

    def _handle_hpo_trial(self, trial_info):
        """Processes a single Hyperparameter Optimization (HPO) trial."""
        self._log(f"Received HPO trial: {trial_info.trial_id}", "Running HPO")
        self._log(f"Hyperparameters: {dict(trial_info.hyperparameters)}", "Running HPO")

        self._log("Simulating HPO trial run...", "Computing")
        time.sleep(5)
        
        score = random.uniform(0.85, 0.99)
        self._log(f"Trial {trial_info.trial_id} finished with score: {score:.4f}", "Reporting")

        result = coordinator_pb2.HPOResult(
            trial_id=trial_info.trial_id,
            score=score,
            hyperparameters=trial_info.hyperparameters
        )
        self.coordinator_stub.ReportHPOTrialResult(result)
        self._log(f"Reported result for trial {trial_info.trial_id}.", "Idle")

    def _start_heartbeat(self):
        def heartbeat_loop():
            while not self._stop_event.is_set():
                try:
                    self.coordinator_stub.SendHeartbeat(coordinator_pb2.HeartbeatRequest())
                except VersoScaleError as e:
                    self._log(f"Failed to send heartbeat: {e}", "Connection Lost")
                self._stop_event.wait(HEARTBEAT_INTERVAL_SEC)
        
        heartbeat_thread = threading.Thread(target=heartbeat_loop, daemon=True)
        heartbeat_thread.start()

    def _pull_parameters(self):
        self._log("Pulling latest parameters...", "Syncing")
        param_iterator = self.ps_stub.PullParameters(parameter_server_pb2.PullRequest())
        pulled_params = [tf.io.parse_tensor(p.tensor_bytes, out_type=tf.float32) for p in param_iterator]
        for i, var in enumerate(self.model.trainable_variables):
            var.assign(pulled_params[i])
        self._log(f"Updated local model with {len(pulled_params)} tensors.", "Syncing")

    def _push_gradients(self, gradients):
        self._log("Compressing and pushing gradients...", "Syncing")
        def gradient_generator():
            for grad, var in zip(gradients, self.model.trainable_variables):
                quantized_grad = tf.cast(tf.clip_by_value(grad, -1.0, 1.0) * 127.5 + 127.5, tf.uint8)
                yield parameter_server_pb2.GradientChunk(
                    layer_name=var.name,
                    compression=parameter_server_pb2.GradientChunk.QUANTIZED_UINT8,
                    tensor_bytes=tf.io.encode_raw(quantized_grad)
                )
        self.ps_stub.PushGradients(gradient_generator())
        self._log("Gradients successfully pushed.", "Syncing")

    def pause(self): self._paused.clear(); self._log("Worker paused.", "Paused")
    def resume(self): self._paused.set(); self._log("Worker resumed.", "Idle")
    def stop(self): self._stop_event.set(); self._paused.set(); self._log("Stop signal received.", "Stopping")

# --- UI Layer ---
app = Flask(__name__)
worker_log_queue = queue.Queue()
worker_status_queue = queue.Queue()
current_status = {"status": "Initializing", "worker_id": "N/A", "cert_expiry": "N/A"}

# This global variable will be populated by the launch() function.
worker = None

@app.route('/')
def index(): return Response(HTML_CONTENT, mimetype='text/html')

@app.route('/api/status')
def get_status():
    global current_status
    try:
        while not worker_status_queue.empty():
            current_status = worker_status_queue.get_nowait()
    except queue.Empty: pass
    return jsonify(current_status)

@app.route('/api/logs')
def get_logs():
    logs = []
    try:
        while not worker_log_queue.empty(): logs.append(worker_log_queue.get_nowait())
    except queue.Empty: pass
    return jsonify(logs)

@app.route('/api/control/pause', methods=['POST'])
def pause_worker():
    if worker: worker.pause()
    return jsonify({"message": "Worker paused"})

@app.route('/api/control/resume', methods=['POST'])
def resume_worker():
    if worker: worker.resume()
    return jsonify({"message": "Worker resumed"})

HTML_CONTENT = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VersoScale Worker</title>
    <style>
        body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;background-color:#1e1e1e;color:#d4d4d4;margin:0;padding:20px;display:flex;flex-direction:column;height:calc(100vh - 40px);box-sizing:border-box;}
        .header,.info-bar{background-color:#252526;border:1px solid #333;padding:12px 20px;border-radius:8px;margin-bottom:15px;display:flex;justify-content:space-between;align-items:center;flex-shrink:0;}
        .title{font-size:1.6em;font-weight:600;color:#007acc;}
        .status-box{display:flex;align-items:center;gap:15px;}
        .status-label{font-size:1.1em;font-weight:bold;color:#ccc;}
        .status-text{font-family:monospace;background-color:#333;padding:6px 12px;border-radius:5px;font-size:1.1em;color:#4ec9b0;min-width:150px;text-align:center;}
        .controls button{background-color:#007acc;color:#fff;border:none;padding:10px 18px;border-radius:5px;cursor:pointer;font-size:1em;font-weight:500;transition:background-color .2s ease;}
        .controls button:hover{background-color:#005a9e;}
        .info-bar .info-item{display:flex;align-items:center;gap:8px;font-family:monospace;font-size:0.95em;}
        .log-container{flex-grow:1;background-color:#1e1e1e;border:1px solid #333;border-radius:8px;padding:15px;overflow-y:auto;font-family:"Consolas",monospace;font-size:0.9em;line-height:1.6;white-space:pre-wrap;color:#ccc;}
        .log-entry{padding:2px 0;}
        .log-entry .timestamp{color:#6a9955;}
        .log-entry .level-ERROR{color:#f44747;}
        .log-entry .level-WARNING{color:#ffd700;}
        .log-entry .level-CRITICAL{color:#ff8c00;font-weight:bold;}
    </style>
</head>
<body>
    <div class="header">
        <div class="title">VersoScale Worker</div>
        <div class="status-box">
            <div class="status-label">STATUS:</div>
            <div class="status-text" id="status-text">Initializing...</div>
        </div>
        <div class="controls">
            <button id="pause-btn">Pause</button>
            <button id="resume-btn">Resume</button>
        </div>
    </div>
    <div class="info-bar">
        <div class="info-item"><strong>Worker ID:</strong> <span id="worker-id">N/A</span></div>
        <div class="info-item"><strong>Cert Expires:</strong> <span id="cert-expiry">N/A</span></div>
    </div>
    <div class="log-container" id="log-container"></div>
    <script>
        const statusText=document.getElementById('status-text'),logContainer=document.getElementById('log-container'),pauseBtn=document.getElementById('pause-btn'),resumeBtn=document.getElementById('resume-btn'),workerIdEl=document.getElementById('worker-id'),certExpiryEl=document.getElementById('cert-expiry');
        function addLogMessage(message){const timestamp=new Date().toLocaleTimeString();const logEntry=document.createElement('div');let levelClass='';if(message.includes("ERROR")||message.includes("Failed")){levelClass='level-ERROR';}if(message.includes("CRITICAL")){levelClass='level-CRITICAL';}if(message.includes("Warning")){levelClass='level-WARNING';}
        logEntry.innerHTML=`<span class="timestamp">[${timestamp}]</span> <span class="${levelClass}">${message.replace(/</g,"&lt;").replace(/>/g,"&gt;")}</span>`;logContainer.appendChild(logEntry);logContainer.scrollTop=logContainer.scrollHeight;}
        async function fetchStatus(){try{const response=await fetch('/api/status');const data=await response.json();statusText.textContent=data.status||'Unknown';workerIdEl.textContent=data.worker_id||'N/A';certExpiryEl.textContent=data.cert_expiry||'N/A';}catch(error){statusText.textContent='Offline';console.error('Error fetching status:',error);}}
        async function fetchLogs(){try{const response=await fetch('/api/logs');const logs=await response.json();logs.forEach(addLogMessage);}catch(error){console.error('Error fetching logs:',error);}}
        pauseBtn.addEventListener('click',()=>fetch('/api/control/pause',{method:'POST'}));resumeBtn.addEventListener('click',()=>fetch('/api/control/resume',{method:'POST'}));
        addLogMessage("Frontend initialized. Awaiting worker status...");setInterval(fetchStatus,1500);setInterval(fetchLogs,2000);
    </script>
</body>
</html>
"""

def launch(registration_token: str):
    """
    Initializes and starts the TrainingWorker and its associated UI. This function
    is designed to be called from the new `runner.py` script.

    Args:
        registration_token: The one-time token for registering with the coordinator.
    """
    global worker
    worker = TrainingWorker(
        coordinator_grpc_addr=COORDINATOR_GRPC_ADDRESS,
        coordinator_https_addr=COORDINATOR_HTTPS_ADDRESS,
        ps_addr=PARAMETER_SERVER_ADDRESS,
        registration_token=registration_token,
        log_queue=worker_log_queue,
        status_queue=worker_status_queue,
    )
    worker.start()
    worker.resume()

    print("Starting Flask web server for UI at http://127.0.0.1:5000")
    # Disabling the reloader is important when running Flask in a threaded application
    app.run(host='127.0.0.1', port=5000, use_reloader=False)

# The old __main__ block has been removed as this script is no longer the primary entry point.
# The new entry point is `runner.py`.
