export interface CodePreset {
  id: string;
  name: string;
  category: "Security" | "Performance" | "Reliability";
  description: string;
  code: string;
}

export const PRESETS: CodePreset[] = [
  {
    id: "sql-injection",
    name: "Preset 1: SQL Injection & Auth Flaw",
    category: "Security",
    description: "Vulnerable to SQL Injection via dynamic f-string query formatting and plaintext credentials.",
    code: `import sqlite3

def authenticate_user(username: str, password_hash: str):
    """Authenticates user with direct string interpolated query."""
    conn = sqlite3.connect("production.db")
    cursor = conn.cursor()
    
    # CRITICAL: Vulnerable to SQL Injection (OWASP A03:2021)
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password_hash}'"
    cursor.execute(query)
    
    user = cursor.fetchone()
    conn.close()
    return user

def delete_user_account(user_id: str):
    conn = sqlite3.connect("production.db")
    cursor = conn.cursor()
    # Another unescaped SQL statement
    cursor.execute(f"DELETE FROM users WHERE id = {user_id}")
    conn.commit()
    conn.close()
`
  },
  {
    id: "quadratic-leak",
    name: "Preset 2: O(N²) Loop & Resource Leak",
    category: "Performance",
    description: "Quadratic algorithmic bottleneck on large lists and unclosed file descriptor leak.",
    code: `import time
from typing import List

def find_duplicate_transactions(batch_a: List[str], batch_b: List[str]) -> List[str]:
    """Finds intersection using an O(N^2) quadratic nested loop."""
    duplicates = []
    
    # PERFORMANCE BOTTLENECK: O(N^2) nested loop over unindexed lists
    for item_a in batch_a:
        for item_b in batch_b:
            if item_a == item_b:
                duplicates.append(item_a)
                
    return duplicates

def export_audit_log(records: List[str], log_path: str):
    # RESOURCE LEAK: File opened without context manager (with open)
    f = open(log_path, "a")
    for record in records:
        f.write(f"AUDIT: {record}\\n")
    # Missing f.close() if an error occurs!
`
  },
  {
    id: "secrets-eval",
    name: "Preset 3: Hardcoded API Key & Unhandled Errors",
    category: "Reliability",
    description: "Plaintext hardcoded API secrets, unsafe eval() execution, and anti-pattern bare except.",
    code: `import os

# SECURITY: Hardcoded production secrets in source control
OPENAI_API_KEY = "sk-proj-99887766554433221100aabbccddeeff"
DATABASE_URL = "postgres://admin:SuperSecretPass123!@db.internal:5432/app"

def parse_user_expression(raw_input: str):
    """Executes arbitrary mathematical code from untrusted user input."""
    try:
        # CRITICAL: Remote Code Execution (RCE) via eval()
        computed_value = eval(raw_input)
        return computed_value
    except:
        # ANTI-PATTERN: Bare except catches KeyboardInterrupt & masks root causes
        pass
    return None

def fetch_external_telemetry(endpoint: str):
    try:
        import requests
        res = requests.get(endpoint, headers={"Authorization": f"Bearer {OPENAI_API_KEY}"})
        return res.json()
    except Exception:
        return {}
`
  },
  {
    id: "multi-vector-pipeline",
    name: "Preset 4: Multi-Vector Pipeline (JWT, Zip Slip, RCE, MD5, DoS)",
    category: "Security",
    description: "Complex real-world pipeline with JWT signature bypass, archive Zip Slip, dynamic eval, MD5 hashing, and process pool DoS.",
    code: `import os
import io
import zipfile
import hashlib
import jwt
import requests
from cryptography.fernet import Fernet
from concurrent.futures import ProcessPoolExecutor

# Hardcoded secret key (Security Flaw: Hardcoded Secret)
SECRET_KEY = "super-secret-jwt-key-change-me"
ENCRYPTION_KEY = b'gAAAAA3v8K...dummy_fernet_key_string...'

def process_document_pipeline(archive_payload, user_jwt_token, destination_dir="/tmp/output"):
    """
    Ingests a ZIP archive of documents, validates the user session via JWT,
    decrypts payload chunks, and processes them concurrently.
    """
    audit_log = {"processed_files": 0, "warnings": [], "security_events": []}

    # 1. Authentication / Token Validation Flaw (none algorithm accepted)
    try:
        decoded_token = jwt.decode(user_jwt_token, SECRET_KEY, algorithms=["HS256", "none"])
        user_role = decoded_token.get("role", "guest")
    except Exception as e:
        audit_log["security_events"].append(f"Authentication failed: {str(e)}")
        return {"error": "Unauthorized"}

    if user_role not in ["admin", "editor"]:
        audit_log["security_events"].append("Insufficient privileges.")
        return {"error": "Forbidden"}

    # 2. Path Traversal Vulnerability (Zip Slip)
    try:
        archive_bytes = bytes.fromhex(archive_payload)
        zip_buffer = io.BytesIO(archive_bytes)
    except Exception as parse_err:
        return {"error": f"Invalid payload format: {str(parse_err)}" }

    extracted_files = []
    with zipfile.ZipFile(zip_buffer, 'r') as zf:
        for filename in zf.namelist():
            target_path = os.path.join(destination_dir, filename)
            zf.extract(filename, destination_dir)
            extracted_files.append(target_path)

    # 3. Cryptographic Flaws & Remote Code Execution
    def parse_document(file_path):
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            # Vulnerability: Weak hashing algorithm
            file_hash = hashlib.md5(content).hexdigest()
            
            # Vulnerability: Arbitrary dynamic eval execution
            if b"EXEC_EVAL" in content:
                eval(content.decode('utf-8').split("EXEC_EVAL:")[1])

            cipher = Fernet(ENCRYPTION_KEY)
            decrypted_text = cipher.decrypt(content).decode('utf-8', errors='ignore')

            # 4. Server-Side Request Forgery (SSRF)
            if "webhook_target=" in decrypted_text:
                webhook_url = decrypted_text.split("webhook_target=")[1].split("\\n")[0].strip()
                requests.post(webhook_url, json={"status": "processed", "hash": file_hash}, timeout=10)

            return f"Successfully processed {file_path}"
        except Exception as file_err:
            return f"Error processing {file_path}: {str(file_err)}"

    # 5. Resource Exhaustion / Process Pool DoS
    with ProcessPoolExecutor(max_workers=os.cpu_count() * 4) as pool:
        futures = [pool.submit(parse_document, path) for path in extracted_files]
        for f in futures:
            result_msg = f.result()
            audit_log["warnings"].append(result_msg)
            audit_log["processed_files"] += 1

    return audit_log
`
  }
];
