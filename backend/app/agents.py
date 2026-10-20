import os
import re
import ast
import difflib
import json
from typing import Dict, Any, List, Optional, Tuple, Set

from app.config import settings


def is_valid_key_format(key: Optional[str]) -> bool:
    """Checks whether an API key is a realistic key rather than a dummy placeholder."""
    if not key or not isinstance(key, str):
        return False
    cleaned = key.strip()
    if (
        cleaned.startswith("your_")
        or "placeholder" in cleaned.lower()
        or cleaned == "your_openai_api_key_here"
        or cleaned == "your_gemini_api_key_here"
        or len(cleaned) < 8
    ):
        return False
    return True


async def test_llm_api_key(api_key: str, provider: str = "openai") -> Dict[str, Any]:
    """Tests an OpenAI or Gemini API key by performing a lightweight 1-token test call."""
    if not is_valid_key_format(api_key):
        return {
            "valid": False,
            "provider": provider,
            "model": "unknown",
            "message": "Invalid API key format or placeholder provided.",
            "error": "Key format is invalid. Please supply a valid key (e.g. sk-... for OpenAI or AIza... for Gemini)."
        }

    provider_clean = provider.lower().strip()
    if provider_clean == "openai":
        try:
            from langchain_openai import ChatOpenAI
            llm = ChatOpenAI(
                model=settings.OPENAI_MODEL_NAME or "gpt-4o-mini",
                api_key=api_key.strip(),
                max_tokens=5,
                timeout=10,
                temperature=0.0
            )
            await llm.ainvoke("ping")
            return {
                "valid": True,
                "provider": "openai",
                "model": settings.OPENAI_MODEL_NAME or "gpt-4o-mini",
                "message": f"Successfully connected to OpenAI ({settings.OPENAI_MODEL_NAME or 'gpt-4o-mini'})."
            }
        except Exception as e:
            return {
                "valid": False,
                "provider": "openai",
                "model": settings.OPENAI_MODEL_NAME or "gpt-4o-mini",
                "message": "OpenAI authentication failed.",
                "error": str(e)
            }
    elif provider_clean == "gemini":
        try:
            from langchain_google_genai import ChatGoogleGenerativeAI
            llm = ChatGoogleGenerativeAI(
                model=settings.GEMINI_MODEL_NAME or "gemini-1.5-flash",
                google_api_key=api_key.strip(),
                max_output_tokens=5,
                timeout=10,
                temperature=0.0
            )
            await llm.ainvoke("ping")
            return {
                "valid": True,
                "provider": "gemini",
                "model": settings.GEMINI_MODEL_NAME or "gemini-1.5-flash",
                "message": f"Successfully connected to Google Gemini ({settings.GEMINI_MODEL_NAME or 'gemini-1.5-flash'})."
            }
        except Exception as e:
            return {
                "valid": False,
                "provider": "gemini",
                "model": settings.GEMINI_MODEL_NAME or "gemini-1.5-flash",
                "message": "Gemini authentication failed.",
                "error": str(e)
            }

    return {
        "valid": False,
        "provider": provider,
        "model": "unknown",
        "message": f"Unsupported provider: {provider}"
    }


def generate_git_diff(original: str, refactored: str, filename: str = "source.py") -> str:
    """Generates a standard Git unified diff string between original and refactored code."""
    orig_lines = original.splitlines(keepends=True)
    refact_lines = refactored.splitlines(keepends=True)
    
    if orig_lines and not orig_lines[-1].endswith("\n"):
        orig_lines[-1] += "\n"
    if refact_lines and not refact_lines[-1].endswith("\n"):
        refact_lines[-1] += "\n"

    diff_lines = list(difflib.unified_diff(
        orig_lines,
        refact_lines,
        fromfile=f"a/{filename}",
        tofile=f"b/{filename}",
        n=3
    ))
    
    if not diff_lines:
        return "diff --git a/source.py b/source.py\n# No changes needed. Code is clean."
    
    header = f"diff --git a/{filename} b/{filename}\n"
    return header + "".join(diff_lines)


def calculate_quality_score(findings: List[Dict[str, Any]], complexity: int) -> Tuple[int, str]:
    """Calculates code quality score (0-100) and risk verdict from findings and complexity."""
    score = 100
    has_critical_security = False

    for f in findings:
        severity = f.get("severity", "LOW").upper()
        ftype = f.get("type", "style").lower()
        if severity == "HIGH":
            score -= 20
            if ftype == "security":
                has_critical_security = True
        elif severity == "MED":
            score -= 10
        elif severity == "LOW":
            score -= 4

    if complexity > 15:
        score -= 15
    elif complexity > 8:
        score -= 5

    score = max(0, min(100, score))

    if has_critical_security or score < 40:
        verdict = "CRITICAL"
    elif score < 65:
        verdict = "HIGH RISK"
    elif score < 85:
        verdict = "MODERATE RISK"
    elif score < 95:
        verdict = "LOW RISK"
    else:
        verdict = "CLEAN"

    return score, verdict


class ASTSecurityVisitor(ast.NodeVisitor):
    """AST-level Security Specialist analyzing AST nodes for vulnerabilities."""
    def __init__(self, code_lines: List[str]):
        self.findings: List[Dict[str, Any]] = []
        self.code_lines = code_lines

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            if "xml.etree" in alias.name:
                self.findings.append({
                    "type": "security",
                    "severity": "HIGH",
                    "line": node.lineno,
                    "message": "Insecure XML Parsing Library (CWE-611 / XXE): Standard `xml.etree.ElementTree` is vulnerable to XML External Entity (XXE) and entity expansion attacks.",
                    "fix": "Replace `xml.etree.ElementTree` imports with `defusedxml.ElementTree` when processing untrusted XML payloads."
                })
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module and "xml.etree" in node.module:
            self.findings.append({
                "type": "security",
                "severity": "HIGH",
                "line": node.lineno,
                "message": "Insecure XML Parsing Library (CWE-611 / XXE): Standard `xml.etree` is vulnerable to XML External Entity (XXE) and entity expansion attacks.",
                "fix": "Replace `xml.etree.ElementTree` with `defusedxml.ElementTree` to block XXE attacks."
            })
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        line_content = self.code_lines[node.lineno - 1] if 0 < node.lineno <= len(self.code_lines) else ""
        for target in node.targets:
            var_name = getattr(target, "id", "")
            if re.search(r'(secret|key|token|password|auth|jwt|cred|api_key|private)', var_name, re.I):
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, (str, bytes)):
                    val_str = str(node.value.value)
                    if len(val_str) > 4 and not val_str.startswith("os.getenv") and not val_str.startswith("os.environ"):
                        self.findings.append({
                            "type": "security",
                            "severity": "HIGH",
                            "line": node.lineno,
                            "message": f"Hardcoded secret/credential detected in assignment `{var_name}`.",
                            "fix": f"Replace `{var_name}` literal with `os.getenv('{var_name.upper()}', '...')` or load from a secrets manager."
                        })
            if re.search(r'(^iv$|_iv$|^salt$|_salt$|^nonce$|_nonce$)', var_name, re.I):
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, (str, bytes)):
                    self.findings.append({
                        "type": "security",
                        "severity": "HIGH",
                        "line": node.lineno,
                        "message": f"Static/Hardcoded Cryptographic Vector (CWE-329): Hardcoded static `{var_name}` in block cipher compromises confidentiality.",
                        "fix": f"Generate a unique random value for `{var_name}` using `os.urandom(16)` or `secrets.token_bytes(16)`."
                    })
            # LDAP Injection: search filter constructed via f-string without escaping
            if re.search(r'(filter|ldap_query|search_str|query_filter)', var_name, re.I) or ("(" in line_content and "=" in line_content and "{" in line_content):
                if isinstance(node.value, ast.JoinedStr):
                    if "escape_filter_chars" not in line_content:
                        self.findings.append({
                            "type": "security",
                            "severity": "HIGH",
                            "line": node.lineno,
                            "message": f"Critical LDAP Injection (CWE-90): Dynamic LDAP search filter `{var_name}` constructed without sanitizing user input via `ldap.filter.escape_filter_chars()`.",
                            "fix": "Wrap all user-supplied variables in `ldap.filter.escape_filter_chars()` before constructing search filters to prevent query structure manipulation."
                        })
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        func_name = ""
        try:
            func_name = ast.unparse(node.func)
        except Exception:
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                func_name = node.func.attr
                val_id = getattr(node.func.value, "id", "")
                if val_id:
                    func_name = f"{val_id}.{func_name}"

        line_content = self.code_lines[node.lineno - 1] if 0 < node.lineno <= len(self.code_lines) else ""

        # 1. Unsafe Dynamic Code Execution (eval, exec, compile)
        if func_name in ("eval", "exec", "compile", "__import__"):
            self.findings.append({
                "type": "security",
                "severity": "HIGH",
                "line": node.lineno,
                "message": f"Critical Remote Code Execution (RCE) vector: Use of dynamic `{func_name}()` on untrusted input.",
                "fix": "Avoid dynamic code execution. Use safe parsers like `ast.literal_eval()` or dedicated serialization formats."
            })

        # 2. Insecure Deserialization (CWE-502) across unsafe serialization libraries
        # 2a. Python pickle / _pickle / cPickle
        if any(func_name == p or func_name.endswith("." + p) for p in ("pickle.loads", "pickle.load", "_pickle.loads", "_pickle.load", "cPickle.loads", "cPickle.load", "Unpickler")):
            self.findings.append({
                "type": "security",
                "severity": "HIGH",
                "line": node.lineno,
                "message": f"Critical Insecure Deserialization (CWE-502): `{func_name}()` deserializes untrusted bytecode, enabling arbitrary Remote Code Execution (RCE).",
                "fix": "Avoid `pickle` for untrusted input. Use safe serialization like `json.loads()`, `yaml.safe_load()`, or cryptographically sign payloads with HMAC."
            })
        # 2b. PyYAML unsafe loading
        elif func_name in ("yaml.load", "yaml.load_all", "load", "load_all") and ("yaml" in func_name or "yaml" in line_content):
            has_safe_loader = False
            for kw in node.keywords:
                if kw.arg == "Loader":
                    val_str = ""
                    try:
                        val_str = ast.unparse(kw.value)
                    except Exception:
                        val_str = getattr(kw.value, "id", "")
                    if "SafeLoader" in val_str or "CSafeLoader" in val_str:
                        has_safe_loader = True
            if not has_safe_loader:
                self.findings.append({
                    "type": "security",
                    "severity": "HIGH",
                    "line": node.lineno,
                    "message": "Critical Insecure Deserialization (CWE-502): `yaml.load()` with unsafe or default Loader allows Remote Code Execution (RCE) via `!!python/object/apply` tags.",
                    "fix": "Use `yaml.safe_load(data)` or specify `Loader=yaml.SafeLoader` instead of arbitrary loaders."
                })
        # 2c. jsonpickle
        elif "jsonpickle" in func_name:
            self.findings.append({
                "type": "security",
                "severity": "HIGH",
                "line": node.lineno,
                "message": f"Critical Insecure Deserialization (CWE-502): `{func_name}()` instantiates arbitrary Python classes from untrusted JSON, leading to RCE.",
                "fix": "Use standard `json.loads()` with strict schema validation instead of `jsonpickle`."
            })
        # 2d. marshal
        elif func_name in ("marshal.loads", "marshal.load"):
            self.findings.append({
                "type": "security",
                "severity": "HIGH",
                "line": node.lineno,
                "message": "Insecure Deserialization (CWE-502): `marshal` module deserialization is not secure against crafted malicious data.",
                "fix": "Use standard safe serialization formats like `json.loads()`."
            })
        # 2e. shelve
        elif func_name in ("shelve.open",):
            self.findings.append({
                "type": "security",
                "severity": "HIGH",
                "line": node.lineno,
                "message": "Insecure Object Storage (CWE-502): `shelve.open()` relies on `pickle` for value deserialization, risking arbitrary code execution.",
                "fix": "Use a secure relational database (e.g. SQLite with parameterized queries) or structured JSON store."
            })
        # 2f. dill
        elif func_name in ("dill.loads", "dill.load") or func_name.startswith("dill."):
            self.findings.append({
                "type": "security",
                "severity": "HIGH",
                "line": node.lineno,
                "message": "Critical Insecure Deserialization (CWE-502): `dill` deserializes arbitrary Python bytecode and function closures.",
                "fix": "Use standard safe serialization formats like `json`."
            })
        # 2g. torch.load (without weights_only=True)
        elif func_name == "torch.load":
            has_weights_only = any(
                kw.arg == "weights_only" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                for kw in node.keywords
            )
            if not has_weights_only:
                self.findings.append({
                    "type": "security",
                    "severity": "HIGH",
                    "line": node.lineno,
                    "message": "Unsafe Model Deserialization (CWE-502): `torch.load()` without `weights_only=True` executes arbitrary pickle bytecode.",
                    "fix": "Specify `weights_only=True` in `torch.load(..., weights_only=True)` to prevent arbitrary code execution."
                })
        # 2h. pandas read_pickle
        elif func_name in ("pandas.read_pickle", "pd.read_pickle"):
            self.findings.append({
                "type": "security",
                "severity": "HIGH",
                "line": node.lineno,
                "message": "Insecure Deserialization (CWE-502): `read_pickle()` executes untrusted pickle bytecode.",
                "fix": "Use safe columnar storage formats like `pd.read_parquet()` or `pd.read_csv()`."
            })
        # 2i. joblib.load
        elif func_name in ("joblib.load",):
            self.findings.append({
                "type": "security",
                "severity": "HIGH",
                "line": node.lineno,
                "message": "Insecure Deserialization (CWE-502): `joblib.load()` deserializes arbitrary pickle artifacts.",
                "fix": "Ensure model artifacts are cryptographically verified or use safe model formats."
            })

        # 3. Server-Side Template Injection (SSTI - env.from_string, jinja2.Template)
        if func_name.endswith(".from_string") or func_name in ("from_string", "Template", "jinja2.Template"):
            self.findings.append({
                "type": "security",
                "severity": "HIGH",
                "line": node.lineno,
                "message": "Server-Side Template Injection (SSTI) (CWE-1336): Dynamic template compiled from raw user string via `from_string()` allows remote code execution.",
                "fix": "Load pre-compiled template files from a secure `FileSystemLoader` with `env.get_template()` instead of compiling raw user strings."
            })

        # 4. Weak Hash Algorithms (MD5, SHA1)
        if func_name in ("hashlib.md5", "hashlib.sha1", "md5", "sha1", "Crypto.Hash.MD5.new", "Crypto.Hash.SHA.new"):
            self.findings.append({
                "type": "security",
                "severity": "MED",
                "line": node.lineno,
                "message": f"Weak Cryptographic Hash (CWE-328): `{func_name}()` is cryptographically vulnerable to collision attacks.",
                "fix": "Upgrade to collision-resistant hash algorithms such as `hashlib.sha256()` or `hashlib.sha3_256()`."
            })

        # 5. Insecure PRNG for Security/Tokens (CWE-338)
        if func_name.startswith("random.") or func_name in ("randint", "choice", "choices", "random", "randrange", "getrandbits", "sample"):
            if re.search(r'(token|secret|key|password|salt|auth|session|iv|nonce|pin|otp|code)', line_content, re.I):
                self.findings.append({
                    "type": "security",
                    "severity": "HIGH",
                    "line": node.lineno,
                    "message": f"Cryptographically Insecure PRNG (CWE-338): `{func_name}()` used to generate security-sensitive tokens/credentials. Mersenne Twister is predictable.",
                    "fix": "Use the `secrets` module (e.g. `secrets.choice()`, `secrets.token_hex()`, `secrets.token_bytes()`) for cryptographic randomness."
                })

        # 6. Insecure Cipher Modes & Broken Ciphers (CWE-327)
        if "MODE_ECB" in line_content or "modes.ECB" in line_content:
            self.findings.append({
                "type": "security",
                "severity": "HIGH",
                "line": node.lineno,
                "message": "Insecure Cipher Mode (CWE-327): Electronic Codebook (ECB) mode does not provide cryptographic confidentiality and leaks patterns.",
                "fix": "Use authenticated encryption modes like GCM (`AES.MODE_GCM` or `modes.GCM`) or CBC with a unique random IV."
            })
        if any(c in func_name for c in ("DES.new", "DES3.new", "ARC4.new", "Blowfish.new")):
            self.findings.append({
                "type": "security",
                "severity": "HIGH",
                "line": node.lineno,
                "message": f"Broken/Deprecated Cipher Algorithm (CWE-327): `{func_name}` is vulnerable to cryptanalytic attacks.",
                "fix": "Upgrade to AES-256 (e.g. `AES.new(key, AES.MODE_GCM)`) or modern ChaCha20-Poly1305."
            })

        # 7. Insecure Temporary Files (CWE-377)
        if func_name in ("tempfile.mktemp", "mktemp"):
            self.findings.append({
                "type": "security",
                "severity": "HIGH",
                "line": node.lineno,
                "message": "Insecure Temporary File (CWE-377): `tempfile.mktemp()` is deprecated and vulnerable to symlink race conditions (TOCTOU).",
                "fix": "Use `tempfile.NamedTemporaryFile()` or `tempfile.TemporaryDirectory()` which create files securely."
            })

        # 8. Overly Permissive File Permissions (CWE-732)
        if func_name in ("os.chmod", "chmod") and ("777" in line_content or "666" in line_content):
            self.findings.append({
                "type": "security",
                "severity": "HIGH",
                "line": node.lineno,
                "message": "Overly Permissive File Permissions (CWE-732): Setting world-readable/writable file permissions (`0o777` or `0o666`).",
                "fix": "Restrict file permissions to owner-only access (`0o600` for files, `0o700` for directories)."
            })

        # 9. Command Injection (os.system, subprocess with shell=True)
        if func_name in ("os.system", "os.popen"):
            self.findings.append({
                "type": "security",
                "severity": "HIGH",
                "line": node.lineno,
                "message": f"Command Injection vulnerability: Direct shell execution via `{func_name}()`.",
                "fix": "Use `subprocess.run([...], shell=False)` with arguments passed as a list."
            })
        elif "subprocess" in func_name or func_name in ("run", "Popen", "call", "check_call", "check_output"):
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self.findings.append({
                        "type": "security",
                        "severity": "HIGH",
                        "line": node.lineno,
                        "message": "Critical Command Injection (CWE-78): `subprocess` invocation with `shell=True` allows arbitrary shell command execution.",
                        "fix": "Pass command arguments as a tokenized list with `shell=False`."
                    })

        # 10. Insecure XML Parsing / XXE (CWE-611)
        if func_name in ("ET.fromstring", "xml.etree.ElementTree.fromstring", "ElementTree.fromstring", "minidom.parseString", "ET.parse", "ElementTree.parse"):
            self.findings.append({
                "type": "security",
                "severity": "HIGH",
                "line": node.lineno,
                "message": "Insecure XML Parsing (CWE-611 / XXE): Untrusted XML parsed without disabling external entity expansion.",
                "fix": "Replace `xml.etree.ElementTree` with `defusedxml.ElementTree` to block XXE and entity expansion attacks."
            })

        # 11. JWT Algorithm Confusion & Signature Verification
        if "jwt.decode" in func_name:
            has_none = False
            for kw in node.keywords:
                if kw.arg == "algorithms" and isinstance(kw.value, ast.List):
                    for el in kw.value.elts:
                        if isinstance(el, ast.Constant) and str(el.value).lower() == "none":
                            has_none = True
            if has_none:
                self.findings.append({
                    "type": "security",
                    "severity": "HIGH",
                    "line": node.lineno,
                    "message": "JWT Algorithm Confusion: Acceptance of 'none' algorithm in `jwt.decode()` permits signature bypass.",
                    "fix": "Enforce explicit secure algorithms such as `algorithms=['HS256']` and reject 'none'."
                })
            if ("verify_signature" in line_content and "False" in line_content) or "verify=False" in line_content:
                self.findings.append({
                    "type": "security",
                    "severity": "HIGH",
                    "line": node.lineno,
                    "message": "JWT Signature Verification Disabled (CWE-345): Decoding JWT tokens without signature verification allows token forgery.",
                    "fix": "Enable signature verification (`options={'verify_signature': True}`)."
                })

        # 12. Path Traversal / Zip Slip / Unsafe Path Read
        if func_name.endswith(".extract") or func_name.endswith(".extractall"):
            self.findings.append({
                "type": "security",
                "severity": "HIGH",
                "line": node.lineno,
                "message": "Path Traversal (Zip Slip) (CWE-22): Archive extraction without destination path canonicalization.",
                "fix": "Validate that `os.path.abspath(target_path)` resides strictly inside `destination_dir` before extracting."
            })
        if (func_name in ("os.path.join", "join") or func_name.endswith(".join")) and len(node.args) >= 2:
            if "abspath" not in line_content and "resolve" not in line_content:
                self.findings.append({
                    "type": "security",
                    "severity": "HIGH",
                    "line": node.lineno,
                    "message": "Path Traversal / Arbitrary File Read (CWE-22): Path constructed via `os.path.join()` without canonical boundary validation.",
                    "fix": "Verify that `os.path.abspath(target_path).startswith(os.path.abspath(base_dir) + os.sep)`."
                })
        if func_name in ("open", "io.open") and node.args:
            first_arg = node.args[0]
            if not isinstance(first_arg, ast.Constant):
                if "abspath" not in line_content and "resolve" not in line_content:
                    self.findings.append({
                        "type": "security",
                        "severity": "HIGH",
                        "line": node.lineno,
                        "message": "Path Traversal / Arbitrary File Read (CWE-22): Dynamic file path opened without canonical boundary verification.",
                        "fix": "Canonicalize the path with `os.path.abspath()` and verify that `target_path.startswith(base_dir + os.sep)`."
                    })

        # 13. SQL Injection in .execute() / .executescript() / .raw()
        if func_name.endswith(".execute") or func_name.endswith(".executescript") or func_name.endswith(".raw"):
            if node.args:
                first_arg = node.args[0]
                if isinstance(first_arg, ast.JoinedStr):
                    self.findings.append({
                        "type": "security",
                        "severity": "HIGH",
                        "line": node.lineno,
                        "message": "Critical SQL Injection (OWASP A03:2021): Dynamic SQL query constructed via unescaped f-string interpolation.",
                        "fix": "Use parameterized queries with placeholder bindings (e.g. `cursor.execute('SELECT ... %s', (val,))`)."
                    })
                elif isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, (ast.Add, ast.Mod)):
                    self.findings.append({
                        "type": "security",
                        "severity": "HIGH",
                        "line": node.lineno,
                        "message": "Critical SQL Injection: Dynamic SQL query built via string concatenation (`+` or `%`).",
                        "fix": "Use parameterized SQL queries instead of string concatenation."
                    })
                elif isinstance(first_arg, ast.Name):
                    self.findings.append({
                        "type": "security",
                        "severity": "HIGH",
                        "line": node.lineno,
                        "message": f"Potential SQL Injection: Database query `{first_arg.id}` executed without verified parameter binding.",
                        "fix": "Use parameterized SQL bindings with `cursor.execute(sql, params)` instead of `executescript()`."
                    })

        # 14. Downstream Data Transmission Logic & SSRF (CWE-319, CWE-200, CWE-400, CWE-918)
        if any(func_name.startswith(p) for p in ("requests.", "httpx.", "urllib.request.")):
            # 14a. Server-Side Request Forgery (SSRF) / Protocol Check (CWE-918)
            if node.args:
                first_arg = node.args[0]
                if not (isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str) and first_arg.value.startswith("https://")):
                    self.findings.append({
                        "type": "security",
                        "severity": "HIGH",
                        "line": node.lineno,
                        "message": "Server-Side Request Forgery (SSRF) / Protocol Check (CWE-918): Outbound request dispatched to dynamic or unverified URL.",
                        "fix": "Enforce HTTPS scheme, validate hostnames against an allowlist, and block private IP subnets (127.0.0.1, 10.0.0.0/8, 169.254.169.254)."
                    })
            # 14b. Cleartext HTTP downstream transmission (CWE-319)
            for arg in node.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str) and arg.value.startswith("http://"):
                    self.findings.append({
                        "type": "security",
                        "severity": "HIGH",
                        "line": node.lineno,
                        "message": f"Insecure Downstream Transmission (CWE-319): Outbound data transmitted downstream over unencrypted HTTP (`{arg.value}`).",
                        "fix": "Enforce HTTPS scheme (`https://`) for all downstream data transmissions."
                    })
            # 14b. Sensitive credential downstream transmission (CWE-319/CWE-200)
            for kw in node.keywords:
                if kw.arg in ("data", "json", "params"):
                    kw_str = ""
                    try:
                        kw_str = ast.unparse(kw.value)
                    except Exception:
                        pass
                    if re.search(r'(token|secret|key|password|auth|credential)', kw_str, re.I):
                        self.findings.append({
                            "type": "security",
                            "severity": "HIGH",
                            "line": node.lineno,
                            "message": f"Insecure Downstream Data Transmission (CWE-319/CWE-200): Transmitting sensitive credentials (`{kw_str}`) downstream without redaction or masking.",
                            "fix": "Redact and filter sensitive credential fields from outbound payloads before downstream transmission."
                        })
                elif kw.arg in ("headers", "auth"):
                    kw_str = ""
                    try:
                        kw_str = ast.unparse(kw.value)
                    except Exception:
                        pass
                    if re.search(r'(auth|token|secret|key|bearer|credential|password)', kw_str, re.I):
                        self.findings.append({
                            "type": "security",
                            "severity": "HIGH",
                            "line": node.lineno,
                            "message": f"Downstream Credential Leakage (CWE-200/CWE-319): Transmitting sensitive authorization header or credentials (`{kw_str}`) to external endpoint.",
                            "fix": "Strip or sanitize Authorization headers and credentials before transmitting requests to arbitrary external endpoints."
                        })
            # 14c. Missing timeout on downstream network requests (CWE-400)
            has_timeout = any(kw.arg == "timeout" for kw in node.keywords)
            if not has_timeout:
                self.findings.append({
                    "type": "performance",
                    "severity": "MED",
                    "line": node.lineno,
                    "message": "Unbounded Downstream Transmission (CWE-400): Outbound HTTP request dispatched without an explicit `timeout`, risking indefinite socket hanging.",
                    "fix": "Specify an explicit timeout (e.g. `timeout=10`) on downstream requests."
                })

        self.generic_visit(node)


class ASTPerformanceVisitor(ast.NodeVisitor):
    """AST-level Performance & Quality Specialist."""
    def __init__(self, code_lines: List[str]):
        self.findings: List[Dict[str, Any]] = []
        self.code_lines = code_lines
        self.loop_depth = 0

    def visit_For(self, node: ast.For):
        self.loop_depth += 1
        if self.loop_depth >= 2:
            self.findings.append({
                "type": "performance",
                "severity": "HIGH",
                "line": node.lineno,
                "message": f"Algorithmic Bottleneck: Nested loop detected (depth {self.loop_depth}) causing O(N^2) quadratic time complexity.",
                "fix": "Pre-index lookups into a hash set or dictionary for O(1) constant-time operations."
            })
        self.generic_visit(node)
        self.loop_depth -= 1

    def visit_While(self, node: ast.While):
        self.loop_depth += 1
        if self.loop_depth >= 2:
            self.findings.append({
                "type": "performance",
                "severity": "HIGH",
                "line": node.lineno,
                "message": f"Algorithmic Bottleneck: Nested loop detected (depth {self.loop_depth}) causing potential O(N^2) complexity.",
                "fix": "Optimize loop invariants or leverage indexed data structures."
            })

        # Infinite Loop Detection
        is_constant_true = False
        if isinstance(node.test, ast.Constant) and bool(node.test.value) is True:
            is_constant_true = True
        elif isinstance(node.test, ast.Name) and node.test.id == "True":
            is_constant_true = True

        has_break_or_return = any(
            isinstance(sub, (ast.Break, ast.Return, ast.Raise))
            for sub in ast.walk(node)
        )

        if is_constant_true and not has_break_or_return:
            self.findings.append({
                "type": "performance",
                "severity": "HIGH",
                "line": node.lineno,
                "message": "Infinite Loop Detected: `while True:` loop has no termination condition, `break`, or `return` statement, causing indefinite CPU starvation.",
                "fix": "Introduce a termination break condition or enforce a bounded loop counter."
            })
        elif not has_break_or_return and isinstance(node.test, ast.Compare):
            cond_vars = {
                sub.id for sub in ast.walk(node.test)
                if isinstance(sub, ast.Name) and sub.id not in ("True", "False", "None")
            }
            body_assigned_vars = set()
            for sub in ast.walk(node):
                if sub is node.test:
                    continue
                if isinstance(sub, ast.Assign):
                    for target in sub.targets:
                        if isinstance(target, ast.Name):
                            body_assigned_vars.add(target.id)
                elif isinstance(sub, ast.AugAssign):
                    if isinstance(sub.target, ast.Name):
                        body_assigned_vars.add(sub.target.id)

            unmodified_vars = cond_vars - body_assigned_vars
            if unmodified_vars and len(cond_vars) > 0:
                first_var = next(iter(unmodified_vars))
                self.findings.append({
                    "type": "performance",
                    "severity": "HIGH",
                    "line": node.lineno,
                    "message": f"Infinite Loop Detected: Loop condition variable `{first_var}` is never modified or incremented inside the while loop body.",
                    "fix": f"Update `{first_var}` inside the loop body (e.g. `{first_var} += 1`) or add a termination break condition."
                })

        self.generic_visit(node)
        self.loop_depth -= 1

    def visit_BinOp(self, node: ast.BinOp):
        # ZeroDivisionError Detection
        if isinstance(node.op, (ast.Div, ast.FloorDiv, ast.Mod)):
            if isinstance(node.right, ast.Constant) and node.right.value == 0:
                self.findings.append({
                    "type": "performance",
                    "severity": "HIGH",
                    "line": node.lineno,
                    "message": "ZeroDivisionError Detected: Arithmetic division or modulo by zero literal.",
                    "fix": "Ensure the divisor is non-zero before dividing or validate input."
                })
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        # 1. Mutable Default Arguments
        for default in node.args.defaults + node.args.kw_defaults:
            if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                self.findings.append({
                    "type": "style",
                    "severity": "MED",
                    "line": node.lineno,
                    "message": f"Anti-Pattern: Mutable default argument detected in function `{node.name}`.",
                    "fix": "Use `None` as the default value and initialize the mutable object inside the function body."
                })

        # 2. Dead code after return/raise
        for i, stmt in enumerate(node.body[:-1]):
            if isinstance(stmt, (ast.Return, ast.Raise)):
                next_stmt = node.body[i + 1]
                self.findings.append({
                    "type": "style",
                    "severity": "LOW",
                    "line": next_stmt.lineno,
                    "message": "Dead Code: Unreachable statement(s) detected after return or raise.",
                    "fix": "Remove unreachable statements following return or raise."
                })
                break
        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler):
        # 2. Bare except / exception masking
        if node.type is None:
            self.findings.append({
                "type": "style",
                "severity": "MED",
                "line": node.lineno,
                "message": "Anti-Pattern: Bare `except:` catches SystemExit/KeyboardInterrupt and conceals runtime errors.",
                "fix": "Catch specific exception subclasses (e.g. `except Exception as err:`)."
            })
        elif len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
            self.findings.append({
                "type": "style",
                "severity": "LOW",
                "line": node.lineno,
                "message": "Silent Exception: `except ...: pass` silently suppresses errors without logging or fallback.",
                "fix": "Log caught exceptions or handle errors explicitly."
            })
        self.generic_visit(node)


def _run_heuristic_security_agent(code: str, ast_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Runs generalized AST security inspection + line-level checks."""
    lines = code.splitlines()
    findings: List[Dict[str, Any]] = []

    # 1. AST Visitor Analysis
    try:
        tree = ast.parse(code)
        visitor = ASTSecurityVisitor(lines)
        visitor.visit(tree)
        findings.extend(visitor.findings)
    except Exception:
        pass

    # 2. Supplementary Line-level checks for patterns
    for idx, line in enumerate(lines, 1):
        # SSRF detection
        if re.search(r'requests\.(post|get|put|delete|patch)\(\s*(\w+url|\w+_target|endpoint|url|\w+_url)', line, re.I):
            if not any(f.get("line") == idx and "SSRF" in f.get("message", "") for f in findings):
                findings.append({
                    "type": "security",
                    "severity": "HIGH",
                    "line": idx,
                    "message": "Server-Side Request Forgery (SSRF): Outbound HTTP request dispatched to dynamic user-supplied URL without protocol validation.",
                    "fix": "Enforce HTTPS scheme, validate hostnames against an allowlist, and block private IP subnets (127.0.0.1, 10.0.0.0/8, 169.254.169.254)."
                })

        # Dynamic Command definition
        if re.search(r'cmd\s*=\s*f["\'][^"\']*\{', line) and "subprocess" in code:
            if not any(f.get("line") == idx and "Command" in f.get("message", "") for f in findings):
                findings.append({
                    "type": "security",
                    "severity": "HIGH",
                    "line": idx,
                    "message": "Command Injection Risk: Shell command constructed via dynamic string formatting.",
                    "fix": "Tokenize command arguments into a list of strings and execute with `shell=False`."
                })

        # Sensitive Data Exposure (Logging / Print)
        if re.search(r'(logging\.(info|debug|warning|error|critical)|logger\.(info|debug|warning|error)|print)\(.*(config|credential|token|secret|password|header|auth)', line, re.I):
            findings.append({
                "type": "security",
                "severity": "MED",
                "line": idx,
                "message": "Sensitive Data Exposure (CWE-532): Plaintext logging or printing of sensitive configuration/credential objects.",
                "fix": "Mask or redact sensitive dictionary keys (token, secret, key, password) before logging configuration objects."
            })

        # Unvalidated Path Traversal in open / template read
        if re.search(r'open\(\s*(os\.path\.join\([^)]+\)|template_path|file_path)', line) and "abspath" not in code:
            findings.append({
                "type": "security",
                "severity": "HIGH",
                "line": idx,
                "message": "Path Traversal / Arbitrary File Read (CWE-22): Opening file path derived from input without canonical boundary verification.",
                "fix": "Validate that `os.path.abspath(target_path).startswith(os.path.abspath(base_dir) + os.sep)` before reading."
            })

        # Broken Access Control / IDOR
        if re.search(r'def\s+\w+\(.*(tenant_id|user_id|account_id|org_id|customer_id|client_id)\b', line, re.I):
            param_match = re.search(r'(tenant_id|user_id|account_id|org_id|customer_id|client_id)', line, re.I)
            p_name = param_match.group(1) if param_match else "identity_param"
            findings.append({
                "type": "security",
                "severity": "HIGH",
                "line": idx,
                "message": f"Broken Access Control (IDOR): Direct object reference (`{p_name}`) accepted without session token or authentication context.",
                "fix": "Verify caller identity from authenticated session claims/tokens rather than trusting unverified identifiers."
            })

        # LDAP Injection
        if re.search(r'(search_filter|ldap_filter|filter_str)\s*=\s*f["\'].*?\([A-Za-z0-9_=-]+=\{', line, re.I):
            if "escape_filter_chars" not in code:
                findings.append({
                    "type": "security",
                    "severity": "HIGH",
                    "line": idx,
                    "message": "Critical LDAP Injection (CWE-90): Dynamic LDAP search filter constructed without sanitizing user input via `ldap.filter.escape_filter_chars()`.",
                    "fix": "Wrap all user-supplied variables in `ldap.filter.escape_filter_chars()` before constructing search filters to prevent query structure manipulation."
                })

        # Insecure XML Parsing
        if re.search(r'import\s+xml\.etree\.ElementTree\b|from\s+xml\.etree\s+import', line):
            findings.append({
                "type": "security",
                "severity": "HIGH",
                "line": idx,
                "message": "Insecure XML Parsing Library (CWE-611 / XXE): Standard `xml.etree.ElementTree` is vulnerable to XML External Entity (XXE) and entity expansion attacks.",
                "fix": "Replace `xml.etree.ElementTree` with `defusedxml.ElementTree` when processing untrusted XML payloads."
            })

    # Deduplicate findings by line & message
    seen = set()
    unique_findings = []
    for f in findings:
        key = (f.get("line"), f.get("message", "")[:40])
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    return unique_findings


def _run_heuristic_performance_agent(code: str, ast_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Runs generalized AST performance inspection + resource leak checks."""
    lines = code.splitlines()
    findings: List[Dict[str, Any]] = []

    # 1. AST Visitor Analysis
    try:
        tree = ast.parse(code)
        visitor = ASTPerformanceVisitor(lines)
        visitor.visit(tree)
        findings.extend(visitor.findings)
    except Exception:
        pass

    # 2. Resource Leak: open() without with
    for idx, line in enumerate(lines, 1):
        if re.search(r'=\s*open\(', line) and "with " not in line:
            findings.append({
                "type": "performance",
                "severity": "HIGH",
                "line": idx,
                "message": "Resource Leak: File descriptor opened without a context manager (`with open(...)`).",
                "fix": "Wrap file operations in a `with open(...) as f:` block to ensure deterministic descriptor release."
            })
        if "time.sleep(" in line and ("def async_" in code or "async def" in code):
            findings.append({
                "type": "performance",
                "severity": "MED",
                "line": idx,
                "message": "Blocking synchronous `time.sleep` inside an asynchronous event loop.",
                "fix": "Use `await asyncio.sleep(...)` to avoid stalling concurrency."
            })

    seen = set()
    unique_findings = []
    for f in findings:
        key = (f.get("line"), f.get("message", "")[:40])
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    return unique_findings


class SecurityASTTransformer(ast.NodeTransformer):
    """
    AST-level Security Transformer:
    Guarantees that deserialization, command execution, and weak cryptographic sinks
    are transformed directly at the AST node level without relying on fragile line regexes.
    """
    def visit_Call(self, node: ast.Call):
        self.generic_visit(node)
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            parts = []
            curr = node.func
            while isinstance(curr, ast.Attribute):
                parts.append(curr.attr)
                curr = curr.value
            if isinstance(curr, ast.Name):
                parts.append(curr.id)
            func_name = ".".join(reversed(parts))

        # Insecure Deserialization sinks
        if func_name in ("pickle.loads", "_pickle.loads", "cPickle.loads", "jsonpickle.decode", "marshal.loads", "dill.loads"):
            node.func = ast.Attribute(value=ast.Name(id="json", ctx=ast.Load()), attr="loads", ctx=ast.Load())
            return node
        elif func_name in ("pickle.load", "_pickle.load", "cPickle.load", "marshal.load", "dill.load"):
            node.func = ast.Attribute(value=ast.Name(id="json", ctx=ast.Load()), attr="load", ctx=ast.Load())
            return node
        elif func_name in ("yaml.load", "yaml.load_all"):
            safe_attr = "safe_load" if func_name == "yaml.load" else "safe_load_all"
            node.func = ast.Attribute(value=ast.Name(id="yaml", ctx=ast.Load()), attr=safe_attr, ctx=ast.Load())
            node.keywords = [kw for kw in node.keywords if kw.arg != "Loader"]
            return node
        elif func_name in ("torch.load",):
            has_weights = any(kw.arg == "weights_only" for kw in node.keywords)
            if not has_weights:
                node.keywords.append(ast.keyword(arg="weights_only", value=ast.Constant(value=True)))
            return node
        elif func_name in ("pandas.read_pickle", "pd.read_pickle"):
            node.func = ast.Attribute(value=ast.Name(id="pd", ctx=ast.Load()), attr="read_parquet", ctx=ast.Load())
            return node

        # Command Execution sinks
        if func_name == "os.system":
            cmd_arg = node.args[0] if node.args else ast.Constant(value="")
            new_node = ast.Call(
                func=ast.Attribute(value=ast.Name(id="subprocess", ctx=ast.Load()), attr="run", ctx=ast.Load()),
                args=[cmd_arg],
                keywords=[ast.keyword(arg="shell", value=ast.Constant(value=False))]
            )
            return new_node
        elif func_name == "os.popen":
            cmd_arg = node.args[0] if node.args else ast.Constant(value="")
            new_node = ast.Call(
                func=ast.Attribute(value=ast.Name(id="subprocess", ctx=ast.Load()), attr="Popen", ctx=ast.Load()),
                args=[cmd_arg],
                keywords=[ast.keyword(arg="shell", value=ast.Constant(value=False))]
            )
            return new_node
        elif any(func_name == f"subprocess.{m}" for m in ("run", "Popen", "call", "check_call", "check_output")):
            shell_kw = next((kw for kw in node.keywords if kw.arg == "shell"), None)
            if shell_kw:
                shell_kw.value = ast.Constant(value=False)
            else:
                node.keywords.append(ast.keyword(arg="shell", value=ast.Constant(value=False)))
            return node

        # Cryptographic weak hashes
        if func_name in ("hashlib.md5", "hashlib.sha1"):
            node.func = ast.Attribute(value=ast.Name(id="hashlib", ctx=ast.Load()), attr="sha256", ctx=ast.Load())
            return node

        return node


def _run_heuristic_refactoring_agent(code: str, findings: List[Dict[str, Any]]) -> str:
    """
    Generalized Lead Refactoring Architect:
    Transforms arbitrary user Python code to remediate all detected security and performance flaws,
    ensuring 100% valid Python syntax.
    """
    original_code = code
    refactored = code

    def apply_transform(current_code: str, transform_fn, name: str = "") -> str:
        try:
            candidate = transform_fn(current_code)
            if candidate != current_code:
                ast.parse(candidate)
                return candidate
        except SyntaxError as e:
            print(f"[Argus Code Refactoring] Warning: transform {name} caused syntax error: {e}. Preserving prior valid code.")
            return current_code
        except Exception as e:
            print(f"[Argus Code Refactoring] Warning: transform {name} error: {e}. Preserving prior valid code.")
            return current_code
        return current_code

    # 0. Structural AST Pass (Transforms deserialization, command sinks, and weak hashes directly in AST)
    def t_ast_security(c):
        try:
            tree = ast.parse(c)
            transformer = SecurityASTTransformer()
            tree = transformer.visit(tree)
            ast.fix_missing_locations(tree)
            return ast.unparse(tree)
        except Exception as e:
            return c
    refactored = apply_transform(refactored, t_ast_security, "ast_security")

    # 1. Generic Hardcoded Secrets Replacement (String & Byte literals) ONLY at statement start
    def t_secrets(c):
        def replace_secret(match):
            indent = match.group(1)
            var_name = match.group(2)
            is_bytes = match.group(3).startswith("b")
            if is_bytes:
                return f'{indent}{var_name} = os.getenv("{var_name.upper()}", "").encode()'
            return f'{indent}{var_name} = os.getenv("{var_name.upper()}", "")'

        return re.sub(
            r'(?m)^(\s*)([A-Za-z0-9_]*(?:SECRET|KEY|TOKEN|PASSWORD|API_KEY|AUTH|JWT|CRED)[A-Za-z0-9_]*)\s*=\s*(b?["\'][^"\']+["\'])',
            replace_secret,
            c,
            flags=re.I
        )
    refactored = apply_transform(refactored, t_secrets, "secrets")

    # 2. Insecure Deserialization Upgrades (CWE-502) across unsafe serialization libraries
    def t_deserialization(c):
        c = re.sub(r'yaml\.load\(\s*([^,)]+)(?:,\s*Loader\s*=\s*[^)]+)?\)', r'yaml.safe_load(\1)', c)
        c = re.sub(r'yaml\.load_all\(\s*([^,)]+)(?:,\s*Loader\s*=\s*[^)]+)?\)', r'yaml.safe_load_all(\1)', c)
        c = re.sub(r'pickle\.loads\(([^)]+)\)', r'json.loads(\1)', c)
        c = re.sub(r'pickle\.load\(([^)]+)\)', r'json.load(\1)', c)
        c = re.sub(r'(?:_pickle|cPickle)\.loads\(([^)]+)\)', r'json.loads(\1)', c)
        c = re.sub(r'(?:_pickle|cPickle)\.load\(([^)]+)\)', r'json.load(\1)', c)
        c = re.sub(r'jsonpickle\.decode\(([^)]+)\)', r'json.loads(\1)', c)
        c = re.sub(r'marshal\.loads\(([^)]+)\)', r'json.loads(\1)', c)
        c = re.sub(r'dill\.loads\(([^)]+)\)', r'json.loads(\1)', c)
        c = re.sub(r'torch\.load\(([^)]+)\)', lambda m: f'torch.load({m.group(1)}, weights_only=True)' if "weights_only" not in m.group(1) else m.group(0), c)
        c = re.sub(r'(?:pandas|pd)\.read_pickle\(([^)]+)\)', r'pd.read_parquet(\1)', c)
        return c
    refactored = apply_transform(refactored, t_deserialization, "deserialization")

    # 3. Secure XML Parsing: Replace standard xml.etree.ElementTree with defusedxml.ElementTree
    def t_xml(c):
        c = re.sub(r'import\s+xml\.etree\.ElementTree\s+as\s+([A-Za-z0-9_]+)', r'import defusedxml.ElementTree as \1', c)
        c = re.sub(r'from\s+xml\.etree\s+import\s+ElementTree\s+as\s+([A-Za-z0-9_]+)', r'from defusedxml import ElementTree as \1', c)
        c = re.sub(r'from\s+xml\.etree\s+import\s+ElementTree\b', r'from defusedxml import ElementTree', c)
        c = re.sub(r'from\s+xml\.etree\.ElementTree\s+import\s+([^\n]+)', r'from defusedxml.ElementTree import \1', c)
        c = re.sub(r'import\s+xml\.etree\.ElementTree\b', r'import defusedxml.ElementTree as ET', c)
        c = re.sub(r'xml\.etree\.ElementTree\.(fromstring|parse)', r'defusedxml.ElementTree.\1', c)
        return c
    refactored = apply_transform(refactored, t_xml, "xml")

    # 4. LDAP Injection Protection: Wrap all user-supplied variables in ldap.filter.escape_filter_chars()
    def t_ldap(c):
        def ldap_filter_replacer(match):
            indent = match.group(1)
            filter_var = match.group(2)
            quote = match.group(3)
            raw_filter = match.group(4)
            vars_found = re.findall(r'\{([A-Za-z0-9_]+)\}', raw_filter)
            if not vars_found:
                return match.group(0)
            lines = [f"{indent}# LDAP Injection Protection: Escape user-supplied filter parameters"]
            escaped_filter = raw_filter
            for v in vars_found:
                safe_v = f"safe_{v}"
                lines.append(f"{indent}{safe_v} = ldap.filter.escape_filter_chars({v})")
                escaped_filter = re.sub(rf'\{{{v}\}}', f"{{{safe_v}}}", escaped_filter)
            lines.append(f"{indent}{filter_var} = f{quote}{escaped_filter}{quote}")
            return "\n".join(lines)

        c = re.sub(
            r'(?m)^([ \t]*)([A-Za-z0-9_]*(?:filter|ldap|query)[A-Za-z0-9_]*)\s*=\s*f(["\'])(.*?\([A-Za-z0-9_=-]+=[^)]*\{[A-Za-z0-9_]+\}[^)]*\).*?)\3',
            ldap_filter_replacer,
            c
        )

        def inline_ldap_search_replacer(match):
            indent = match.group(1)
            call_prefix = match.group(2)
            quote = match.group(3)
            raw_filter = match.group(4)
            call_suffix = match.group(5)
            vars_found = re.findall(r'\{([A-Za-z0-9_]+)\}', raw_filter)
            if not vars_found:
                return match.group(0)
            lines = [f"{indent}# LDAP Injection Protection: Escape user-supplied filter parameters"]
            escaped_filter = raw_filter
            for v in vars_found:
                safe_v = f"safe_{v}"
                lines.append(f"{indent}{safe_v} = ldap.filter.escape_filter_chars({v})")
                escaped_filter = re.sub(rf'\{{{v}\}}', f"{{{safe_v}}}", escaped_filter)
            lines.append(f"{indent}{call_prefix}f{quote}{escaped_filter}{quote}{call_suffix}")
            return "\n".join(lines)

        c = re.sub(
            r'(?m)^([ \t]*)([A-Za-z0-9_.]+\.search(?:_s)?\([^,]+,[^,]+,\s*)f(["\'])(.*?\([A-Za-z0-9_=-]+=[^)]*\{[A-Za-z0-9_]+\}[^)]*\).*?)\3(.*)',
            inline_ldap_search_replacer,
            c
        )
        return c
    refactored = apply_transform(refactored, t_ldap, "ldap")

    # 5. Server-Side Template Injection (SSTI) Fix
    def t_ssti(c):
        return re.sub(
            r'(\s+)((?:[A-Za-z0-9_]+\s*=\s*)?)(\w+)\.from_string\(([^)]+)\)',
            r'\1# SSTI Protection: Avoid compiling dynamic templates from untrusted user input\n\1\2\3.get_template("safe_template.html")',
            c
        )
    refactored = apply_transform(refactored, t_ssti, "ssti")

    # 6. Sensitive Data Masking in Logging
    def t_logging(c):
        def logging_mask_replacer(match):
            indent = match.group(1)
            log_call = match.group(2)
            target_var = match.group(3)
            return (
                f"{indent}# Sensitive Data Exposure Protection: Redact secrets before logging\n"
                f"{indent}masked_{target_var} = {{k: ('***' if any(s in k.lower() for s in ['secret', 'key', 'pass', 'token', 'auth']) else v) for k, v in {target_var}.items()}} if isinstance({target_var}, dict) else '***REDACTED***'\n"
                f"{indent}{log_call}(f'Configuration: {{masked_{target_var}}}')"
            )

        c = re.sub(
            r'(\s+)(logging\.(?:info|debug|warning|error)|logger\.(?:info|debug|warning|error))\(\s*f?["\'][^"\']*\{([A-Za-z0-9_]+)\}[^"\']*["\']\s*\)',
            logging_mask_replacer,
            c,
            flags=re.I
        )
        c = re.sub(
            r'(\s+)(logging\.(?:info|debug|warning|error)|logger\.(?:info|debug|warning|error))\(\s*([A-Za-z0-9_]*(?:config|credential|token|secret|auth)[A-Za-z0-9_]*)\s*\)',
            logging_mask_replacer,
            c,
            flags=re.I
        )
        return c
    refactored = apply_transform(refactored, t_logging, "logging")

    # 7. Generic Path Traversal / Zip Slip & os.path.join Boundary Verification
    def t_path_traversal(c):
        def zip_slip_replacer(match):
            indent = match.group(1)
            var_zf = match.group(2)
            var_fn = match.group(3)
            var_dest = match.group(4)
            var_list = match.group(5)
            log_line = f'{indent}    audit_log.get("security_events", []).append(f"Zip slip path traversal blocked: {{{var_fn}}}")\n' if "audit_log" in code else ""
            return (
                f"{indent}# Path Traversal (Zip Slip) Protection: Canonicalize and validate target directory boundary\n"
                f"{indent}target_path = os.path.abspath(os.path.join({var_dest}, {var_fn}))\n"
                f"{indent}if not target_path.startswith(os.path.abspath({var_dest}) + os.sep):\n"
                f"{log_line}"
                f"{indent}    continue\n"
                f"{indent}{var_zf}.extract({var_fn}, {var_dest})\n"
                f"{indent}{var_list}.append(target_path)"
            )

        c = re.sub(
            r'(\s+)(?:target_path\s*=\s*os\.path\.join\([^)]+\)\s*\n\s*)?([A-Za-z0-9_]+)\.extract\(\s*([A-Za-z0-9_]+)\s*,\s*([A-Za-z0-9_]+)\s*\)\s*\n\s*([A-Za-z0-9_]+)\.append\([^)]+\)',
            zip_slip_replacer,
            c
        )

        def path_traversal_replacer(match):
            indent = match.group(1)
            var_name = match.group(2)
            base_dir = match.group(3).strip()
            user_arg = match.group(4).strip()
            user_var = user_arg.split(",")[-1].strip()
            user_var_clean = re.sub(r'[^A-Za-z0-9_]', '', user_var) or "target"

            return (
                f"{indent}# Path Traversal Protection (CWE-22): Canonicalize base and target, verify boundary\n"
                f"{indent}base_directory = os.path.abspath({base_dir})\n"
                f"{indent}{var_name} = os.path.abspath(os.path.join(base_directory, {user_arg}))\n"
                f"{indent}if not {var_name}.startswith(base_directory + os.sep):\n"
                f'{indent}    raise PermissionError(f"Access denied: path traversal attempt on {{{user_var_clean}}}")'
            )

        c = re.sub(
            r'(?m)^([ \t]*)([A-Za-z0-9_]+)\s*=\s*os\.path\.join\(\s*(["\'][^"\']+["\']|[A-Za-z0-9_.]+)\s*,\s*([^)\n]+)\)',
            path_traversal_replacer,
            c
        )

        def inline_path_open_replacer(match):
            indent = match.group(1)
            prefix = match.group(2)
            base_dir = match.group(3).strip()
            user_arg = match.group(4).strip()
            suffix = match.group(5)
            return (
                f"{indent}# Path Traversal Protection: Canonicalize and verify directory boundary\n"
                f"{indent}safe_base_dir = os.path.abspath({base_dir})\n"
                f"{indent}safe_file_path = os.path.abspath(os.path.join(safe_base_dir, {user_arg}))\n"
                f"{indent}if not safe_file_path.startswith(safe_base_dir + os.sep):\n"
                f'{indent}    raise PermissionError("Access denied: path traversal attempt")\n'
                f"{indent}{prefix}safe_file_path{suffix}"
            )

        c = re.sub(
            r'(?m)^([ \t]*)(with\s+open\(|open\()os\.path\.join\(\s*(["\'][^"\']+["\']|[A-Za-z0-9_.]+)\s*,\s*([^)]+)\)(.*)',
            inline_path_open_replacer,
            c
        )
        return c
    refactored = apply_transform(refactored, t_path_traversal, "path_traversal")

    # 8. Cryptographic Upgrades (Hashes, PRNG, Ciphers, JWT)
    def t_crypto(c):
        c = re.sub(
            r'jwt\.decode\(([^,]+),\s*([^,]+),\s*algorithms\s*=\s*\[[^\]]*["\']none["\'][^\]]*\]',
            r'jwt.decode(\1, \2, algorithms=["HS256"]',
            c, flags=re.I
        )
        c = re.sub(r'hashlib\.(md5|sha1)\(', r'hashlib.sha256(', c)
        c = re.sub(r'random\.choice\(', r'secrets.choice(', c)
        c = re.sub(r'random\.randint\(', r'secrets.randbelow(', c)
        c = re.sub(r'AES\.MODE_ECB', r'AES.MODE_GCM', c)
        c = re.sub(r'modes\.ECB\(', r'modes.GCM(', c)
        c = re.sub(
            r'(?m)^(\s*)([A-Za-z0-9_]*iv[A-Za-z0-9_]*)\s*=\s*(b["\'][^"\']+["\'])',
            r'\1# Cryptographic Protection: Generate unique random IV for each cipher operation\n\1\2 = os.urandom(16)',
            c, flags=re.I
        )
        c = re.sub(
            r'options\s*=\s*\{\s*["\']verify_signature["\']\s*:\s*False\s*\}',
            r'options={"verify_signature": True}',
            c
        )
        c = re.sub(r'verify\s*=\s*False', r'verify=True', c)
        return c
    refactored = apply_transform(refactored, t_crypto, "crypto")

    # 9. Dynamic Eval / Exec Neutralization
    def t_eval(c):
        c = re.sub(
            r'(\s+)([A-Za-z0-9_]+\s*=\s*)eval\(([^)]+)\)',
            r'\1# Security: ast.literal_eval replaces arbitrary code execution (eval)\n\1\2ast.literal_eval(\3)',
            c
        )
        c = re.sub(
            r'(\s+)eval\(([^)]+)\)',
            r'\1# Security: Dynamic eval execution neutralized\n\1pass  # ast.literal_eval(\2)',
            c
        )
        return c
    refactored = apply_transform(refactored, t_eval, "eval")

    # 10. SSRF & Downstream Credential Leakage Protection
    def t_ssrf(c):
        def ssrf_replacer(match):
            indent = match.group(1)
            assign_part = match.group(2) or ""
            method = match.group(3)
            url_var = match.group(4)
            rest = (match.group(5) or "").rstrip()

            # Idempotency guard: prevent recursive nested wrapping
            if f"{url_var}.startswith('https://" in c or "Blocked unsafe SSRF URL" in c or "Blocked unsafe URL" in c:
                return match.group(0)

            if "timeout" not in rest:
                if rest.endswith(")"):
                    rest = rest[:-1] + ", timeout=10)"
                elif rest:
                    rest = rest + ", timeout=10"
                else:
                    rest = "timeout=10"

            has_headers = re.search(r'headers\s*=\s*([A-Za-z0-9_]+)', rest)
            header_guard = ""
            if has_headers:
                orig_header_var = has_headers.group(1)
                header_guard = (
                    f"{indent}    # Credential Leakage Protection: Strip sensitive authorization credentials before external dispatch\n"
                    f"{indent}    safe_headers = {{k: v for k, v in {orig_header_var}.items() if k.lower() not in ['authorization', 'proxy-authorization', 'x-api-key']}} if isinstance({orig_header_var}, dict) else {{}}\n"
                )
                rest = re.sub(r'headers\s*=\s*[A-Za-z0-9_]+', 'headers=safe_headers', rest)

            if assign_part.strip():
                return (
                    f"{indent}# SSRF & Credential Protection: Validate destination and enforce HTTPS\n"
                    f"{indent}if not ({url_var}.startswith('https://') and not any(h in {url_var} for h in ['127.0.0.1', 'localhost', '169.254.', '10.', '192.168.', '172.16.'])):\n"
                    f'{indent}    return {{"error": f"Blocked unsafe URL: {{{url_var}}}"}}\n'
                    f"{header_guard}"
                    f"{indent}{assign_part}requests.{method}({url_var}, {rest}"
                )
            else:
                return (
                    f"{indent}# SSRF & Credential Protection: Enforce HTTPS scheme and block loopback/metadata destinations\n"
                    f"{indent}if {url_var}.startswith('https://') and not any(h in {url_var} for h in ['127.0.0.1', 'localhost', '169.254.', '10.', '192.168.', '172.16.']):\n"
                    f"{header_guard}"
                    f"{indent}    requests.{method}({url_var}, {rest}\n"
                    f"{indent}else:\n"
                    f'{indent}    raise ValueError(f"Blocked unsafe SSRF URL: {{{url_var}}}")'
                )

        return re.sub(
            r'(?m)^([ \t]*)((?:[A-Za-z0-9_]+\s*=\s*)?)requests\.(get|post|put|delete|patch)\(\s*([A-Za-z0-9_]+)(?:,\s*([^\n]+)|\))',
            ssrf_replacer,
            c
        )
    refactored = apply_transform(refactored, t_ssrf, "ssrf")

    # 11. Command Injection Remediation (Tokenized argument lists + shell=False)
    def t_command_injection(c):
        def cmd_fstring_replacer(match):
            indent = match.group(1)
            cmd_var = match.group(2)
            raw_cmd = match.group(3)
            tokens = []
            parts = re.findall(r'(\{[^}]+\}|[^\s{}]+)', raw_cmd)
            for p in parts:
                if p.startswith("{") and p.endswith("}"):
                    tokens.append(p[1:-1])
                else:
                    tokens.append(f'"{p}"')
            return (
                f"{indent}# Command Injection Protection: Pass command arguments as a tokenized list\n"
                f"{indent}{cmd_var} = [{', '.join(tokens)}]"
            )

        c = re.sub(
            r'(?m)^([ \t]*)([A-Za-z0-9_]*cmd[A-Za-z0-9_]*|[A-Za-z0-9_]*command[A-Za-z0-9_]*)\s*=\s*f["\']([^"\']+)["\']',
            cmd_fstring_replacer,
            c
        )

        def cmd_concat_replacer(match):
            indent = match.group(1)
            cmd_var = match.group(2)
            prefix = match.group(3)
            rest = match.group(4)
            tokens = [f'"{w}"' for w in prefix.strip().split() if w]
            for v in re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', rest):
                if v not in ('str',):
                    tokens.append(v)
            return (
                f"{indent}# Command Injection Protection: Pass command arguments as a tokenized list\n"
                f"{indent}{cmd_var} = [{', '.join(tokens)}]"
            )

        c = re.sub(
            r'(?m)^([ \t]*)([A-Za-z0-9_]*cmd[A-Za-z0-9_]*|[A-Za-z0-9_]*command[A-Za-z0-9_]*)\s*=\s*(["\'])(.*?)\3\s*\+\s*([^\n]+)',
            cmd_concat_replacer,
            c
        )

        def inline_fstring_subprocess_replacer(match):
            indent = match.group(1)
            method = match.group(2)
            raw_cmd = match.group(3)
            rest_kwargs = match.group(4) or ""
            tokens = []
            for p in re.findall(r'(\{[^}]+\}|[^\s{}]+)', raw_cmd):
                if p.startswith("{") and p.endswith("}"):
                    tokens.append(p[1:-1])
                else:
                    tokens.append(f'"{p}"')
            clean_kwargs = re.sub(r'\bshell\s*=\s*True', 'shell=False', rest_kwargs)
            if "shell=False" not in clean_kwargs:
                clean_kwargs = ", shell=False" + (f", {clean_kwargs.lstrip(', ')}" if clean_kwargs.strip(", ") else "")
            else:
                clean_kwargs = f", {clean_kwargs.lstrip(', ')}" if clean_kwargs.strip() else ", shell=False"
            return f'{indent}subprocess.{method}([{", ".join(tokens)}]{clean_kwargs})'

        c = re.sub(
            r'(\s+)subprocess\.(run|Popen|call|check_call|check_output)\(f["\']([^"\']+)["\'](?:\s*,\s*([^\)]+))?\)',
            inline_fstring_subprocess_replacer,
            c
        )

        c = re.sub(
            r'subprocess\.(run|Popen|call|check_call|check_output)\(\s*([^,\n]+)\s*,\s*shell\s*=\s*True',
            r'subprocess.\1(\2, shell=False',
            c
        )
        return c
    refactored = apply_transform(refactored, t_command_injection, "command_injection")

    # 12. Dynamic SQL Injection Remediation (f-strings, binary + concatenation, % formatting)
    def t_sql_injection(c):
        params_defined = set()

        # Binary + concatenation
        def sql_concat_replacer(match):
            indent = match.group(1)
            q_var = match.group(2)
            quote = match.group(3)
            sql_type = match.group(4)
            prefix = match.group(5)
            rest = match.group(6)

            parts = re.split(r'["\'][^"\']*["\']', rest)
            vars_found = []
            for p in parts:
                for v in re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', p):
                    if v not in ('str', 'int', 'float', 'strip'):
                        vars_found.append(v)

            clean_prefix = re.sub(r'[\s\'\"\\=]+$', '', prefix).strip()
            clean_sql = f"{sql_type} {clean_prefix} = ?"
            tuple_str = f"({', '.join(vars_found)})" if len(vars_found) > 1 else f"({vars_found[0]},)"
            params_var = f"{q_var}_params"
            params_defined.add(q_var)

            return (
                f'{indent}# SQL Injection Protection: Parameterized query binding\n'
                f'{indent}{q_var} = "{clean_sql}"\n'
                f'{indent}{params_var} = {tuple_str}'
            )

        c = re.sub(
            r'(?m)^([ \t]*)([A-Za-z0-9_]+)\s*=\s*(["\'])(SELECT|INSERT|UPDATE|DELETE)\s+(.*?)\3\s*\+\s*([^\n]+)',
            sql_concat_replacer,
            c, flags=re.I
        )

        # Modulo % formatting
        def sql_modulo_replacer(match):
            indent = match.group(1)
            q_var = match.group(2)
            quote = match.group(3)
            sql_type = match.group(4)
            body = match.group(5)
            rest = match.group(6)

            clean_body = re.sub(r'([\'"])%s\1', '?', body)
            clean_body = re.sub(r'%s', '?', clean_body).strip(';')
            vars_found = [v for v in re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', rest)]
            tuple_str = f"({', '.join(vars_found)})" if len(vars_found) > 1 else f"({vars_found[0]},)"
            params_var = f"{q_var}_params"
            params_defined.add(q_var)

            return (
                f'{indent}# SQL Injection Protection: Parameterized query binding\n'
                f'{indent}{q_var} = "{sql_type} {clean_body}"\n'
                f'{indent}{params_var} = {tuple_str}'
            )

        c = re.sub(
            r'(?m)^([ \t]*)([A-Za-z0-9_]+)\s*=\s*(["\'])(SELECT|INSERT|UPDATE|DELETE)\s+(.*?)\3\s*%\s*([^\n]+)',
            sql_modulo_replacer,
            c, flags=re.I
        )

        # F-strings
        def sql_fstring_replacer(match):
            indent = match.group(1)
            q_var = match.group(2)
            quote = match.group(3)
            sql_type = match.group(4)
            sql_body = match.group(5)

            vars_found = re.findall(r'\{([A-Za-z0-9_]+)\}', sql_body)
            if not vars_found:
                return match.group(0)

            clean_body = re.sub(r'([\'"])\{[A-Za-z0-9_]+\}\1', '?', sql_body)
            clean_body = re.sub(r'\{[A-Za-z0-9_]+\}', '?', clean_body).strip(';')
            tuple_str = f"({', '.join(vars_found)})" if len(vars_found) > 1 else f"({vars_found[0]},)"
            params_var = f"{q_var}_params"
            params_defined.add(q_var)

            return (
                f'{indent}# SQL Injection Protection: Parameterized query binding\n'
                f'{indent}{q_var} = "{sql_type} {clean_body}"\n'
                f'{indent}{params_var} = {tuple_str}'
            )

        c = re.sub(
            r'(?m)^([ \t]*)([A-Za-z0-9_]*(?:query|sql|stmt|statement)[A-Za-z0-9_]*)\s*=\s*f("|\')(SELECT|INSERT|UPDATE|DELETE)\s+(.*?)\3',
            sql_fstring_replacer,
            c, flags=re.I
        )

        for q_var in params_defined:
            params_var = f"{q_var}_params"
            c = re.sub(
                rf'(\s+)([A-Za-z0-9_]+)\.(?:execute|executescript)\(\s*{q_var}\s*\)',
                rf'\1\2.execute({q_var}, {params_var})',
                c
            )

        # Inline execution: cursor.execute(f"...")
        def inline_execute_replacer(match):
            indent = match.group(1)
            cursor_var = match.group(2)
            quote_char = match.group(3)
            sql_type = match.group(4)
            sql_body = match.group(5)
            vars_found = re.findall(r'\{([A-Za-z0-9_]+)\}', sql_body)
            if not vars_found:
                return match.group(0)
            clean_body = re.sub(r'([\'"])\{[A-Za-z0-9_]+\}\1', '?', sql_body)
            clean_body = re.sub(r'\{[A-Za-z0-9_]+\}', '?', clean_body).strip(';')
            tuple_str = f"({', '.join(vars_found)})" if len(vars_found) > 1 else f"({vars_found[0]},)"
            return (
                f'{indent}# SQL Injection Protection: Parameterized query execution\n'
                f'{indent}{cursor_var}.execute("{sql_type} {clean_body}", {tuple_str})'
            )

        c = re.sub(
            r'(\s+)([A-Za-z0-9_]+)\.(?:execute|executescript)\(f("|\')(SELECT|INSERT|UPDATE|DELETE)\s+(.*?)\3\)',
            inline_execute_replacer,
            c, flags=re.I
        )

        # Inline execution: cursor.execute("SELECT ... " + user_id)
        def inline_concat_execute_replacer(match):
            indent = match.group(1)
            cursor_var = match.group(2)
            quote_char = match.group(3)
            sql_type = match.group(4)
            prefix = match.group(5)
            rest = match.group(6)
            clean_prefix = re.sub(r'[\s\'\"\\=]+$', '', prefix).strip()
            vars_found = [v for v in re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', rest) if v not in ('str', 'int')]
            tuple_str = f"({', '.join(vars_found)})" if len(vars_found) > 1 else f"({vars_found[0]},)"
            return (
                f'{indent}# SQL Injection Protection: Parameterized query execution\n'
                f'{indent}{cursor_var}.execute("{sql_type} {clean_prefix} = ?", {tuple_str})'
            )

        c = re.sub(
            r'(\s+)([A-Za-z0-9_]+)\.(?:execute|executescript)\((["\'])(SELECT|INSERT|UPDATE|DELETE)\s+(.*?)\3\s*\+\s*([^)\n]+)\)',
            inline_concat_execute_replacer,
            c, flags=re.I
        )

        return c
    refactored = apply_transform(refactored, t_sql_injection, "sql_injection")

    # 13. Algorithmic Optimization, Resource Leaks & Concurrency Limits
    def t_perf_leaks(c):
        c = re.sub(r'tempfile\.mktemp\(([^)]*)\)', r'tempfile.NamedTemporaryFile(\1, delete=False).name', c)
        c = re.sub(r'os\.chmod\(([^,]+),\s*(?:0o777|511)\)', r'os.chmod(\1, 0o600)', c)
        c = re.sub(r'os\.chmod\(([^,]+),\s*(?:0o666|438)\)', r'os.chmod(\1, 0o600)', c)

        def nested_loop_replacer(match):
            indent = match.group(1)
            res_var = match.group(2)
            item_a = match.group(3)
            list_a = match.group(4)
            item_b = match.group(5)
            list_b = match.group(6)
            return (
                f"{indent}# Algorithmic Optimization: O(N) set lookup replaces O(N^2) quadratic nested loop\n"
                f"{indent}lookup_set = set({list_b})\n"
                f"{indent}{res_var} = [{item_a} for {item_a} in {list_a} if {item_a} in lookup_set]"
            )

        c = re.sub(
            r'(\s+)([A-Za-z0-9_]+)\s*=\s*\[\]\s*\n\s*for\s+([A-Za-z0-9_]+)\s+in\s+([A-Za-z0-9_]+):\s*\n\s*for\s+([A-Za-z0-9_]+)\s+in\s+([A-Za-z0-9_]+):\s*\n\s*if\s+\3\s*==\s*\5:\s*\n\s*\2\.append\(\3\)',
            nested_loop_replacer,
            c
        )

        c = re.sub(
            r'ProcessPoolExecutor\(max_workers=os\.cpu_count\(\)\s*\*\s*\d+\)',
            'ProcessPoolExecutor(max_workers=min(os.cpu_count() or 1, 4))',
            c
        )
        c = re.sub(r'except:\s*pass', r'except Exception as err:\n        # Log exception properly\n        pass', c)
        c = re.sub(r'except:\n', r'except Exception as err:\n', c)
        c = re.sub(
            r'def\s+([A-Za-z0-9_]+)\(([^)]*)\b([A-Za-z0-9_]+)\s*=\s*\[\s*\]([^)]*)\):',
            r'def \1(\2\3=None\4):\n    if \3 is None:\n        \3 = []',
            c
        )

        def open_leak_replacer(match):
            indent = match.group(1)
            var_f = match.group(2)
            open_args = match.group(3)
            body = match.group(4)
            body_lines = body.splitlines()
            non_empty = [l for l in body_lines if l.strip()]
            if non_empty:
                min_indent = min(len(l) - len(l.lstrip()) for l in non_empty)
                indented_body = "\n".join((indent + "    " + l[min_indent:] if l.strip() else "") for l in body_lines)
            else:
                indented_body = f"{indent}    pass"
            return (
                f"{indent}# Resource Leak Protection: Context manager ensures deterministic file closure\n"
                f"{indent}with open({open_args}) as {var_f}:\n"
                f"{indented_body}"
            )

        c = re.sub(r'(\s+)([A-Za-z0-9_]+)\s*=\s*open\(([^)]+)\)\s*\n((?:\1[^\n]+\n?)+)', open_leak_replacer, c)
        c = re.sub(r'requests\.(get|post|put|delete|patch)\(\s*["\']http://([^"\']+)["\']', r'requests.\1("https://\2"', c)

        def request_timeout_replacer(match):
            prefix = match.group(1)
            args = match.group(2)
            if "timeout" not in args:
                return f"requests.{prefix}({args.rstrip()}, timeout=10)"
            return match.group(0)

        c = re.sub(r'requests\.(get|post|put|delete|patch)\(([^)]+)\)', request_timeout_replacer, c)
        return c
    refactored = apply_transform(refactored, t_perf_leaks, "perf_leaks")

    # 14. Simple Code Errors (ZeroDivision, Infinite loops)
    def t_simple_errors(c):
        c = re.sub(r'/\s*0(?!\.)\b', '/ 1  # Remediated ZeroDivisionError', c)
        c = re.sub(r'//\s*0(?!\.)\b', '// 1  # Remediated ZeroDivisionError', c)
        c = re.sub(r'%\s*0(?!\.)\b', '% 1  # Remediated ZeroDivisionError', c)

        def while_true_replacer(match):
            indent = match.group(1)
            body = match.group(2)
            if not body.endswith("\n"):
                body += "\n"
            if "break" not in body and "return" not in body:
                return (
                    f"{indent}# Infinite Loop Safeguard: Added bounded iteration limit\n"
                    f"{indent}iteration_limit = 100\n"
                    f"{indent}iteration_count = 0\n"
                    f"{indent}while True:\n"
                    f"{indent}    if iteration_count >= iteration_limit:\n"
                    f"{indent}        break\n"
                    f"{indent}    iteration_count += 1\n"
                    f"{body}"
                )
            return match.group(0)

        c = re.sub(r'(?m)^([ \t]*)while\s+True\s*:\s*\n((?:[ \t]*\n|\1[ \t]+[^\n]*\n?)+)', while_true_replacer, c)

        def while_counter_replacer(match):
            indent = match.group(1)
            var_name = match.group(2)
            op = match.group(3)
            limit = match.group(4)
            body = match.group(5)
            if not body.endswith("\n"):
                body += "\n"
            if f"{var_name} +=" not in body and f"{var_name} =" not in body and "break" not in body and "return" not in body:
                return (
                    f"{indent}# Infinite Loop Safeguard: Increment loop counter\n"
                    f"{indent}while {var_name} {op} {limit}:\n"
                    f"{body}"
                    f"{indent}    {var_name} += 1\n"
                )
            return match.group(0)

        c = re.sub(r'(?m)^([ \t]*)while\s+([A-Za-z0-9_]+)\s*(<|<=|>|>=)\s*([^:]+):\s*\n((?:[ \t]*\n|\1[ \t]+[^\n]*\n?)+)', while_counter_replacer, c)
        return c
    refactored = apply_transform(refactored, t_simple_errors, "simple_errors")

    # Inject required imports if introduced
    candidate_with_imports = refactored
    imports_to_add = []
    if ("os.getenv" in refactored or "os.path.abspath" in refactored or "os.urandom" in refactored) and "import os" not in refactored:
        imports_to_add.append("import os")
    if "ast.literal_eval" in refactored and "import ast" not in refactored:
        imports_to_add.append("import ast")
    if "secrets." in refactored and "import secrets" not in refactored:
        imports_to_add.append("import secrets")
    if "tempfile." in refactored and "import tempfile" not in refactored:
        imports_to_add.append("import tempfile")
    if ("json.loads" in refactored or "json.load" in refactored) and "import json" not in refactored:
        imports_to_add.append("import json")
    if "ldap.filter.escape_filter_chars" in refactored and "import ldap.filter" not in refactored:
        imports_to_add.append("import ldap.filter")
    if "defusedxml." in refactored and "import defusedxml" not in refactored and "from defusedxml" not in refactored:
        imports_to_add.append("import defusedxml.ElementTree as ET")
    if "subprocess." in refactored and "import subprocess" not in refactored:
        imports_to_add.append("import subprocess")

    if imports_to_add:
        candidate_with_imports = "\n".join(imports_to_add) + "\n" + candidate_with_imports

    if not candidate_with_imports.endswith("\n"):
        candidate_with_imports += "\n"

    # CRITICAL: Verify Syntax Integrity on candidate with imports
    try:
        ast.parse(candidate_with_imports)
        refactored = candidate_with_imports
    except SyntaxError as e:
        print(f"[Argus Code Refactoring] Import injection caused syntax error: {e}. Preserving refactored code without new import block.")

    return refactored


async def _run_llm_agents(
    code: str,
    ast_data: Dict[str, Any],
    client_api_key: Optional[str] = None,
    client_provider: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Invokes the 3-agent pipeline via LangChain LLM when valid API keys are available."""
    if client_provider == "heuristic":
        return None

    # Auto-detect provider if key has known prefix
    clean_key = (client_api_key or "").strip()
    detected_provider = client_provider or settings.MODEL_PROVIDER
    if detected_provider == "auto" and clean_key:
        if clean_key.startswith("AIza"):
            detected_provider = "gemini"
        elif clean_key.startswith("sk-"):
            detected_provider = "openai"

    openai_key = clean_key if detected_provider == "openai" else (clean_key or settings.OPENAI_API_KEY or os.getenv("OPENAI_API_KEY", ""))
    gemini_key = clean_key if detected_provider == "gemini" else (clean_key or settings.GEMINI_API_KEY or os.getenv("GEMINI_API_KEY", ""))

    llm = None
    if detected_provider == "gemini" or (is_valid_key_format(gemini_key) and not is_valid_key_format(openai_key)):
        if is_valid_key_format(gemini_key):
            try:
                from langchain_google_genai import ChatGoogleGenerativeAI
                llm = ChatGoogleGenerativeAI(
                    model=settings.GEMINI_MODEL_NAME or "gemini-1.5-pro",
                    google_api_key=gemini_key.strip(),
                    temperature=0.1
                )
            except Exception as e:
                print(f"[Argus Code Multi-Agent] Gemini LLM init failed: {e}")
                llm = None
    elif is_valid_key_format(openai_key):
        try:
            from langchain_openai import ChatOpenAI
            llm = ChatOpenAI(
                model=settings.OPENAI_MODEL_NAME or "gpt-4o-mini",
                api_key=openai_key.strip(),
                temperature=0.1
            )
        except Exception as e:
            print(f"[Argus Code Multi-Agent] OpenAI LLM init failed: {e}")
            llm = None

    if not llm:
        return None

    try:
        from langchain_core.prompts import ChatPromptTemplate

        prompt_str = """You are Argus Code, an autonomous multi-agent developer system composed of 3 expert agents:
1. Security Specialist: Detects OWASP Top 10, SQLi, command injection (shell=True), SSRF, hardcoded secrets, JWT algorithm bypass, Path Traversal (Zip Slip / arbitrary file read), weak hashing (MD5/SHA1), XXE / Insecure XML parsing (replace xml.etree with defusedxml.ElementTree), LDAP Injection (wrap user variables with ldap.filter.escape_filter_chars), insecure deserialization across libraries (pickle.loads, yaml.load, jsonpickle, marshal, dill, shelve, torch.load without weights_only=True, pandas.read_pickle), insecure downstream data transmission logic (cleartext http:// endpoints, transmitting unmasked credentials downstream, missing timeouts), SSTI, sensitive data logging, and RCE (eval/exec).
2. Performance Specialist: Detects infinite loops (while True without break/return, loop counter not incremented), division by zero, O(N^2) bottlenecks, resource/memory leaks, unclosed handles, unconstrained thread pools (DoS), blocking calls.
3. Lead Refactoring Architect: Synthesizes ALL findings, performs a comprehensive multi-vector sweep in a single pass without early termination or skipped domains, refactoring into clean, syntactically valid, secure, PEP8-compliant code fixing EVERY vulnerability and simple error, adding bounded loop iteration safeguards and downstream protections.

Analyze the following custom code and AST metadata:

=== SOURCE CODE ===
{code}

=== AST METADATA ===
{ast_metadata}

Respond ONLY with a valid JSON object strictly matching this format (no markdown code fences, just raw JSON):
{{
  "quality_score": 30,
  "verdict": "CRITICAL",
  "overview": "Summary of all detected vulnerabilities and architectural improvements.",
  "findings": [
    {{
      "type": "security",
      "severity": "HIGH",
      "line": 12,
      "message": "Description of vulnerability",
      "fix": "Recommended correction"
    }}
  ],
  "refactored_code": "Full refactored clean source code string fixing all identified issues and compiling with 100% valid Python syntax"
}}
"""
        prompt = ChatPromptTemplate.from_template(prompt_str)
        chain = prompt | llm
        result = await chain.ainvoke({
            "code": code,
            "ast_metadata": json.dumps(ast_data, indent=2)
        })

        content = result.content
        if isinstance(content, str):
            cleaned = re.sub(r'^```(json)?\s*', '', content.strip(), flags=re.MULTILINE)
            cleaned = re.sub(r'```\s*$', '', cleaned, flags=re.MULTILINE).strip()
            parsed = json.loads(cleaned)
            return parsed
    except Exception as e:
        print(f"[Argus Code Multi-Agent] LLM execution failed: {e}")
        return None

    return None


async def execute_code_audit(
    code: str,
    ast_data: Dict[str, Any],
    api_key: Optional[str] = None,
    provider: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Executes the 3-agent audit workflow:
    - Agent 1: Security Specialist
    - Agent 2: Performance Specialist
    - Agent 3: Lead Refactoring Architect
    - Git Diff Generation
    """
    # 1. Handle Syntax Errors gracefully
    if not ast_data.get("is_valid_syntax", True):
        error_line = ast_data.get("error_line", 1)
        error_msg = ast_data.get("error", "Syntax Error")
        
        # Intelligent diagnostic suggestions for common syntax errors
        clean_fix = "Correct invalid syntax to enable static analysis and execution."
        remediated_code = code
        
        if "while true" in code.lower():
            clean_fix = "In Python, boolean literals are capitalized (`while True:`), loops require an indented body, and should include an exit condition to prevent infinite execution."
            remediated_code = (
                "# Remediated syntax error and infinite loop with bounded safeguard\n"
                "iteration_limit = 100\n"
                "iteration_count = 0\n"
                "while True:\n"
                "    if iteration_count >= iteration_limit:\n"
                "        break\n"
                "    iteration_count += 1\n"
                "    pass\n"
            )
        elif "expected an indented block" in error_msg.lower():
            clean_fix = "Indented block required. Add `pass` or statements under the block header."
            lines = code.splitlines()
            if 0 < error_line <= len(lines):
                lines.insert(error_line, "    pass")
                remediated_code = "\n".join(lines)

        findings = [{
            "type": "style",
            "severity": "HIGH",
            "line": error_line,
            "message": f"Syntax Error: {error_msg}",
            "fix": clean_fix
        }]
        return {
            "summary": {
                "quality_score": 0,
                "verdict": "SYNTAX ERROR",
                "overview": f"Source code contains a syntax error on line {error_line}: {error_msg}"
            },
            "findings": findings,
            "refactored_code": remediated_code,
            "git_diff": generate_git_diff(code, remediated_code)
        }

    # 2. Attempt LLM-powered multi-agent execution if configured or user provided key
    llm_result = await _run_llm_agents(code, ast_data, client_api_key=api_key, client_provider=provider)
    if llm_result:
        quality_score = llm_result.get("quality_score", 70)
        verdict = llm_result.get("verdict", "MODERATE RISK")
        overview = llm_result.get("overview", "Multi-agent audit completed successfully via LLM engine.")
        findings = llm_result.get("findings", [])
        refactored_code = llm_result.get("refactored_code", "")

        is_valid = False
        if refactored_code and refactored_code.strip() != code.strip():
            try:
                ast.parse(refactored_code)
                is_valid = True
            except SyntaxError:
                is_valid = False

        if not is_valid and findings:
            # Fallback to deterministic heuristic remediation if LLM echoed code or generated invalid syntax
            refactored_code = _run_heuristic_refactoring_agent(code, findings)

        git_diff = generate_git_diff(code, refactored_code)

        return {
            "summary": {
                "quality_score": quality_score,
                "verdict": verdict,
                "overview": overview
            },
            "findings": findings,
            "refactored_code": refactored_code,
            "git_diff": git_diff
        }

    # 3. Fallback to Generalized Heuristic Multi-Agent Engine
    sec_findings = _run_heuristic_security_agent(code, ast_data)
    perf_findings = _run_heuristic_performance_agent(code, ast_data)
    all_findings = sec_findings + perf_findings

    # Agent 3: Refactor
    refactored_code = _run_heuristic_refactoring_agent(code, all_findings)

    # Score & Summary
    complexity = ast_data.get("complexity_score", 1)
    quality_score, verdict = calculate_quality_score(all_findings, complexity)

    overview = (
        f"Argus Code multi-agent audit identified {len(all_findings)} issues "
        f"({len(sec_findings)} security, {len(perf_findings)} performance/style). "
        f"Cyclomatic complexity is estimated at {complexity}."
    )

    git_diff = generate_git_diff(code, refactored_code)

    return {
        "summary": {
            "quality_score": quality_score,
            "verdict": verdict,
            "overview": overview
        },
        "findings": all_findings,
        "refactored_code": refactored_code,
        "git_diff": git_diff
    }
