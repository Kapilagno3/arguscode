import pytest
import asyncio
import ast
from app.parser import extract_ast_metadata
from app.agents import execute_code_audit, test_llm_api_key as check_llm_api_key

PRESET_1 = """import sqlite3

def authenticate_user(username: str, password_hash: str):
    conn = sqlite3.connect("production.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password_hash}'"
    cursor.execute(query)
    user = cursor.fetchone()
    conn.close()
    return user
"""

PRESET_2 = """import time
from typing import List

def find_duplicate_transactions(batch_a: List[str], batch_b: List[str]) -> List[str]:
    duplicates = []
    for item_a in batch_a:
        for item_b in batch_b:
            if item_a == item_b:
                duplicates.append(item_a)
    return duplicates

def export_audit_log(records: List[str], log_path: str):
    f = open(log_path, "a")
    for record in records:
        f.write(f"AUDIT: {record}\\n")
"""

PRESET_3 = """import os

OPENAI_API_KEY = "sk-proj-99887766554433221100aabbccddeeff"

def parse_user_expression(raw_input: str):
    try:
        computed_value = eval(raw_input)
        return computed_value
    except:
        pass
    return None
"""

MEDIA_UPLOAD_CODE = """import os
import subprocess
import xml.etree.ElementTree as ET
import requests
import uuid
import sqlite3

DB_PATH = os.environ.get("ASSET_DB", "assets.db")

def process_media_upload_job(tenant_id, metadata_xml, asset_url, resize_dimensions="100x100"):
    audit_log = {"status": "pending", "errors": []}
    
    if not tenant_id:
        return {"error": "Missing tenant identification"}

    try:
        root = ET.fromstring(metadata_xml)
        asset_title = root.find("Title").text if root.find("Title") is not None else "Untitled"
        asset_category = root.find("Category").text if root.find("Category") is not None else "General"
    except Exception as xml_err:
        audit_log["errors"].append(f"XML parse error: {str(xml_err)}")
        return audit_log

    try:
        response = requests.get(asset_url, stream=True, timeout=15)
        if response.status_code != 200:
            return {"error": "Failed to fetch remote asset"}
        
        temp_filename = f"/tmp/upload_{uuid.uuid4().hex}.dat"
        with open(temp_filename, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
    except Exception as net_err:
        return {"error": f"Network download failed: {str(net_err)}"}

    output_filename = f"/tmp/processed_{uuid.uuid4().hex}.jpg"
    try:
        cmd = f"convert {temp_filename} -resize {resize_dimensions} {output_filename}"
        subprocess.run(cmd, shell=True, check=True, timeout=30)
    except subprocess.CalledProcessError as sub_err:
        audit_log["errors"].append(f"Media conversion failed: {str(sub_err)}")
        if os.path.exists(temp_filename):
            os.remove(temp_filename)
        return audit_log

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        query = f"INSERT INTO assets (tenant_id, title, category, path) VALUES ('{tenant_id}', '{asset_title}', '{asset_category}', '{output_filename}');"
        cursor.executescript(query)
        conn.commit()
        audit_log["status"] = "success"
    except Exception as db_err:
        audit_log["errors"].append(f"DB insert failed: {str(db_err)}")
    finally:
        conn.close()
        if os.path.exists(temp_filename):
            os.remove(temp_filename)

    return audit_log
"""

ADVANCED_VULN_CODE = """import os
import yaml
import logging
import jinja2

TEMPLATE_DIR = "/var/templates"

def render_custom_report(template_name, user_template_str, config_payload):
    # 1. Unsafe YAML Deserialization
    config = yaml.load(config_payload, Loader=yaml.Loader)
    
    # 2. Sensitive Data Exposure (logging secrets)
    logging.info(f"Loaded config: {config}")
    
    # 3. Path Traversal / Arbitrary File Read
    template_path = os.path.join(TEMPLATE_DIR, template_name)
    with open(template_path, "r") as f:
        raw_content = f.read()

    # 4. Server-Side Template Injection (SSTI)
    env = jinja2.Environment()
    template = env.from_string(user_template_str)
    return template.render(config=config)
"""

@pytest.mark.anyio
async def test_audit_preset_1_sql_injection():
    ast_data = extract_ast_metadata(PRESET_1)
    assert ast_data["is_valid_syntax"] is True
    result = await execute_code_audit(PRESET_1, ast_data)
    assert result["summary"]["quality_score"] < 100
    assert any(f["type"] == "security" for f in result["findings"])
    assert "diff --git" in result["git_diff"]
    assert len(result["refactored_code"]) > 0

@pytest.mark.anyio
async def test_audit_preset_2_performance_leak():
    ast_data = extract_ast_metadata(PRESET_2)
    assert ast_data["is_valid_syntax"] is True
    result = await execute_code_audit(PRESET_2, ast_data)
    assert any(f["type"] == "performance" for f in result["findings"])
    assert "diff --git" in result["git_diff"]

@pytest.mark.anyio
async def test_audit_preset_3_secrets_eval():
    ast_data = extract_ast_metadata(PRESET_3)
    assert ast_data["is_valid_syntax"] is True
    result = await execute_code_audit(PRESET_3, ast_data)
    assert any(f["type"] == "security" for f in result["findings"])
    assert any("secret" in f["message"].lower() or "token" in f["message"].lower() for f in result["findings"])
    assert "diff --git" in result["git_diff"]

@pytest.mark.anyio
async def test_audit_media_upload_job_syntax_and_security():
    ast_data = extract_ast_metadata(MEDIA_UPLOAD_CODE)
    assert ast_data["is_valid_syntax"] is True
    result = await execute_code_audit(MEDIA_UPLOAD_CODE, ast_data)
    
    findings_text = " ".join(f["message"] for f in result["findings"])
    assert "Command Injection" in findings_text or "subprocess" in findings_text
    assert "SQL Injection" in findings_text
    assert "SSRF" in findings_text or "Server-Side Request Forgery" in findings_text
    assert "XML" in findings_text
    
    refactored = result["refactored_code"]
    parsed_tree = ast.parse(refactored)
    assert parsed_tree is not None
    assert "shell=False" in refactored

@pytest.mark.anyio
async def test_audit_advanced_vulns():
    ast_data = extract_ast_metadata(ADVANCED_VULN_CODE)
    assert ast_data["is_valid_syntax"] is True
    result = await execute_code_audit(ADVANCED_VULN_CODE, ast_data)
    
    findings_text = " ".join(f["message"] for f in result["findings"])
    # 1. YAML Deserialization
    assert "yaml.load" in findings_text or "Deserialization" in findings_text
    # 2. SSTI
    assert "Template Injection" in findings_text or "SSTI" in findings_text
    # 3. Path Traversal
    assert "Path Traversal" in findings_text or "File Read" in findings_text
    # 4. Sensitive Data Logging
    assert "Sensitive Data" in findings_text or "logging" in findings_text

    refactored = result["refactored_code"]
    assert "yaml.safe_load" in refactored
    parsed_tree = ast.parse(refactored)
    assert parsed_tree is not None

@pytest.mark.anyio
async def test_audit_while_true_syntax_error():
    snippet = "while true:\n"
    ast_data = extract_ast_metadata(snippet)
    assert ast_data["is_valid_syntax"] is False
    assert ast_data["error_line"] == 1
    
    result = await execute_code_audit(snippet, ast_data)
    assert result["summary"]["verdict"] == "SYNTAX ERROR"
    assert result["summary"]["quality_score"] == 0
    assert len(result["findings"]) > 0
    assert "Syntax Error" in result["findings"][0]["message"]
    assert "while True:" in result["refactored_code"]

@pytest.mark.anyio
async def test_test_llm_api_key_invalid_placeholder():
    res = await check_llm_api_key("your_openai_api_key_here", "openai")
    assert res["valid"] is False
    assert "Invalid API key format" in res["message"]


@pytest.mark.anyio
async def test_audit_dynamic_sql_no_cross_contamination():
    """Validates that SQL refactoring dynamically binds the function's own variables with 0 cross-contamination."""
    custom_sql_code = """import sqlite3

def get_employee_salary(dept_id, employee_ssn):
    conn = sqlite3.connect("payroll.db")
    cursor = conn.cursor()
    sql = f"SELECT salary FROM payroll WHERE department = '{dept_id}' AND ssn = '{employee_ssn}'"
    cursor.execute(sql)
    row = cursor.fetchone()
    conn.close()
    return row
"""
    ast_data = extract_ast_metadata(custom_sql_code)
    result = await execute_code_audit(custom_sql_code, ast_data)
    
    findings_text = " ".join(f["message"] for f in result["findings"])
    assert "SQL Injection" in findings_text
    
    refactored = result["refactored_code"]
    # Verify strict syntax integrity
    parsed_tree = ast.parse(refactored)
    assert parsed_tree is not None

    # CRITICAL: Verify ZERO cross-contamination from other prompts/presets
    assert "username" not in refactored
    assert "password_hash" not in refactored
    assert "tenant_id" not in refactored
    assert "asset_title" not in refactored
    assert "output_filename" not in refactored
    assert "audit_log" not in refactored

    # Verify that the actual variables from THIS function are used
    assert "sql_params = (dept_id, employee_ssn)" in refactored
    assert "cursor.execute(sql, sql_params)" in refactored


@pytest.mark.anyio
async def test_audit_filesystem_vectors():
    """Validates detection and remediation of local filesystem vectors: path traversal, mktemp, permissions."""
    fs_code = """import os
import tempfile

def process_cached_file(storage_dir, user_supplied_file):
    target = os.path.join(storage_dir, user_supplied_file)
    with open(target, "r") as f:
        content = f.read()
    
    temp_name = tempfile.mktemp(suffix=".tmp")
    with open(temp_name, "w") as f:
        f.write(content)
        
    os.chmod(temp_name, 0o777)
    return content
"""
    ast_data = extract_ast_metadata(fs_code)
    result = await execute_code_audit(fs_code, ast_data)
    
    findings_text = " ".join(f["message"] for f in result["findings"])
    assert "Path Traversal" in findings_text or "File Read" in findings_text
    assert "mktemp" in findings_text or "Temporary File" in findings_text
    assert "Permissions" in findings_text or "777" in findings_text
    
    refactored = result["refactored_code"]
    parsed_tree = ast.parse(refactored)
    assert parsed_tree is not None
    
    assert "os.path.abspath" in refactored
    assert "startswith" in refactored
    assert "NamedTemporaryFile" in refactored
    assert "0o600" in refactored or "0o700" in refactored


@pytest.mark.anyio
async def test_audit_cryptographic_vectors():
    """Validates detection and remediation of cryptographic vectors: insecure PRNG, ECB mode, static IV, unverified JWT."""
    crypto_code = """import random
import string
import hashlib
import jwt
from Crypto.Cipher import AES

def create_auth_token(length=32):
    chars = string.ascii_letters + string.digits
    api_token = "".join(random.choice(chars) for _ in range(length))
    return api_token

def encrypt_payload(data_bytes, key_bytes):
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    static_iv = b'0123456789abcdef'
    token_hash = hashlib.md5(data_bytes).hexdigest()
    return cipher.encrypt(data_bytes), token_hash

def inspect_jwt(raw_jwt):
    return jwt.decode(raw_jwt, options={"verify_signature": False})
"""
    ast_data = extract_ast_metadata(crypto_code)
    result = await execute_code_audit(crypto_code, ast_data)
    
    findings_text = " ".join(f["message"] for f in result["findings"])
    assert "PRNG" in findings_text or "random" in findings_text
    assert "Cipher Mode" in findings_text or "ECB" in findings_text
    assert "Cryptographic Vector" in findings_text or "static" in findings_text or "IV" in findings_text
    assert "Hash" in findings_text or "md5" in findings_text
    assert "Signature" in findings_text or "JWT" in findings_text
    
    refactored = result["refactored_code"]
    parsed_tree = ast.parse(refactored)
    assert parsed_tree is not None
    
    assert "secrets.choice" in refactored
    assert "import secrets" in refactored
    assert "MODE_GCM" in refactored
    assert "os.urandom" in refactored
    assert "sha256" in refactored
    assert "verify_signature\": True" in refactored


@pytest.mark.anyio
async def test_audit_simple_code_errors():
    """Validates detection and remediation of simple errors: infinite loops and zero division."""
    loop_code = """def simple_runner():
    while True:
        print("polling")
"""
    ast_data = extract_ast_metadata(loop_code)
    result = await execute_code_audit(loop_code, ast_data)
    findings_text = " ".join(f["message"] for f in result["findings"])
    assert "Infinite Loop" in findings_text
    refactored = result["refactored_code"]
    assert "iteration_limit" in refactored or "break" in refactored
    assert ast.parse(refactored) is not None

    counter_code = """def count_up():
    i = 0
    while i < 10:
        print(i)
"""
    ast_data_c = extract_ast_metadata(counter_code)
    result_c = await execute_code_audit(counter_code, ast_data_c)
    findings_text_c = " ".join(f["message"] for f in result_c["findings"])
    assert "Infinite Loop" in findings_text_c or "i" in findings_text_c
    refactored_c = result_c["refactored_code"]
    assert "i += 1" in refactored_c
    assert ast.parse(refactored_c) is not None

    div_code = """def divide_calc(val):
    return val / 0
"""
    ast_data_d = extract_ast_metadata(div_code)
    result_d = await execute_code_audit(div_code, ast_data_d)
    findings_text_d = " ".join(f["message"] for f in result_d["findings"])
    assert "ZeroDivisionError" in findings_text_d
    refactored_d = result_d["refactored_code"]
    assert "/ 0" not in refactored_d
    assert ast.parse(refactored_d) is not None


@pytest.mark.anyio
async def test_audit_insecure_deserialization():
    """Validates static analysis rules and fixes for unsafe serialization libraries."""
    deserial_code = """import pickle
import yaml
import jsonpickle
import torch

def restore_session(raw_bytes, yaml_text, json_payload, model_file):
    state = pickle.loads(raw_bytes)
    config = yaml.load(yaml_text, Loader=yaml.Loader)
    obj = jsonpickle.decode(json_payload)
    weights = torch.load(model_file)
    return state, config, obj, weights
"""
    ast_data = extract_ast_metadata(deserial_code)
    result = await execute_code_audit(deserial_code, ast_data)
    
    findings_text = " ".join(f["message"] for f in result["findings"])
    assert "pickle.loads" in findings_text or "Insecure Deserialization" in findings_text
    assert "yaml.load" in findings_text
    assert "jsonpickle" in findings_text
    assert "torch.load" in findings_text or "weights_only" in findings_text

    refactored = result["refactored_code"]
    assert "yaml.safe_load" in refactored
    assert "json.loads" in refactored
    assert "import json" in refactored
    assert "weights_only=True" in refactored
    assert ast.parse(refactored) is not None


@pytest.mark.anyio
async def test_audit_downstream_data_transmission():
    """Validates static analysis rules and fixes for downstream data transmission logic."""
    downstream_code = """import requests

def forward_webhook(auth_token, user_data):
    endpoint = "http://api.partner.com/events"
    payload = {"api_token": auth_token, "data": user_data}
    res = requests.post(endpoint, json=payload)
    return res.json()
"""
    ast_data = extract_ast_metadata(downstream_code)
    result = await execute_code_audit(downstream_code, ast_data)
    
    findings_text = " ".join(f["message"] for f in result["findings"])
    assert "Downstream Transmission" in findings_text or "HTTP" in findings_text
    assert "timeout" in findings_text

    refactored = result["refactored_code"]
    assert "https://" in refactored
    assert "timeout=10" in refactored
    assert ast.parse(refactored) is not None


@pytest.mark.anyio
async def test_audit_ldap_injection():
    """Validates detection and remediation of LDAP injection using ldap.filter.escape_filter_chars()."""
    ldap_code = """import ldap

def search_directory(username, role_name):
    conn = ldap.initialize("ldap://directory.corp.internal")
    search_filter = f"(&(uid={username})(role={role_name}))"
    results = conn.search_s("dc=corp,dc=internal", ldap.SCOPE_SUBTREE, search_filter)
    return results
"""
    ast_data = extract_ast_metadata(ldap_code)
    result = await execute_code_audit(ldap_code, ast_data)
    
    findings_text = " ".join(f["message"] for f in result["findings"])
    assert "LDAP" in findings_text or "escape_filter_chars" in findings_text
    
    refactored = result["refactored_code"]
    assert "ldap.filter.escape_filter_chars" in refactored
    assert "safe_username" in refactored
    assert "safe_role_name" in refactored
    assert "import ldap.filter" in refactored
    assert ast.parse(refactored) is not None


@pytest.mark.anyio
async def test_audit_secure_xml_defusedxml():
    """Validates replacement of standard xml.etree with defusedxml.ElementTree."""
    xml_code = """import xml.etree.ElementTree as ET

def parse_order_xml(raw_xml_string):
    root = ET.fromstring(raw_xml_string)
    order_id = root.find("OrderId").text
    return order_id
"""
    ast_data = extract_ast_metadata(xml_code)
    result = await execute_code_audit(xml_code, ast_data)
    
    findings_text = " ".join(f["message"] for f in result["findings"])
    assert "XML" in findings_text or "defusedxml" in findings_text
    
    refactored = result["refactored_code"]
    assert "defusedxml.ElementTree as ET" in refactored
    assert "xml.etree.ElementTree" not in refactored
    assert ast.parse(refactored) is not None


@pytest.mark.anyio
async def test_comprehensive_multi_vector_sweep_single_pass():
    """Validates that all vulnerabilities across deserialization, path traversal, command/SQL injection,
    LDAP, XML, and protocol checks are patched in a single pass without early termination or skipped domains."""
    multi_code = """import os
import subprocess
import requests
import random
import yaml
import sqlite3
import xml.etree.ElementTree as ET

def execute_pipeline(user_id, raw_yaml, raw_xml, dest_dir, filename, api_url, ldap_user):
    # 1. Insecure Deserialization
    config = yaml.load(raw_yaml, Loader=yaml.Loader)
    
    # 2. Secure XML parsing
    root = ET.fromstring(raw_xml)
    
    # 3. Path traversal
    file_path = os.path.join(dest_dir, filename)
    with open(file_path, "w") as f:
        f.write("data")
        
    # 4. Command injection
    cmd = f"echo processing {file_path}"
    subprocess.run(cmd, shell=True)
    
    # 5. SQL injection
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM accounts WHERE owner = '{user_id}'"
    cursor.execute(query)
    
    # 6. LDAP injection
    search_filter = f"(&(sAMAccountName={ldap_user}))"
    
    # 7. Protocol check / SSRF
    resp = requests.get(api_url)
    
    # 8. Cryptographic PRNG
    token = "".join(random.choice("0123456789") for _ in range(16))
    
    # 9. Infinite loop
    while True:
        pass
        
    return config, token
"""
    ast_data = extract_ast_metadata(multi_code)
    result = await execute_code_audit(multi_code, ast_data)
    
    findings_text = " ".join(f["message"] for f in result["findings"])
    
    # Verify all domains detected
    assert "yaml.load" in findings_text
    assert "XML" in findings_text or "defusedxml" in findings_text
    assert "Path Traversal" in findings_text
    assert "Command Injection" in findings_text
    assert "SQL" in findings_text
    assert "LDAP" in findings_text
    assert "SSRF" in findings_text or "Protocol" in findings_text
    assert "PRNG" in findings_text or "random" in findings_text
    assert "Infinite Loop" in findings_text
    
    refactored = result["refactored_code"]
    
    # Verify all domains patched in a single pass
    assert "yaml.safe_load" in refactored
    assert "defusedxml.ElementTree" in refactored
    assert "os.path.abspath" in refactored
    assert "shell=False" in refactored
    assert "query_params" in refactored or "params" in refactored
    assert "ldap.filter.escape_filter_chars" in refactored
    assert "safe_ldap_user" in refactored
    assert "timeout=" in refactored
    assert "secrets.choice" in refactored
    assert "iteration_limit" in refactored or "break" in refactored
    
    # Verify complete AST syntax validity of refactored code
    parsed = ast.parse(refactored)
    assert parsed is not None



