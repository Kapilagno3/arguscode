from datetime import datetime, timezone
import os
from fastapi import APIRouter, HTTPException

from app.schemas import (
    AuditRequest,
    AuditResponse,
    HealthResponse,
    TestKeyRequest,
    TestKeyResponse,
    ASTMetadata,
    AuditSummary,
    Finding,
)
from app.parser import extract_ast_metadata
from app.agents import execute_code_audit, test_llm_api_key, is_valid_key_format
from app.config import settings

router = APIRouter(tags=["Argus Code API"])


@router.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint to verify backend operational readiness and provider configuration."""
    has_openai = is_valid_key_format(settings.OPENAI_API_KEY or os.getenv("OPENAI_API_KEY", ""))
    has_gemini = is_valid_key_format(settings.GEMINI_API_KEY or os.getenv("GEMINI_API_KEY", ""))
    
    active = "heuristic"
    if settings.MODEL_PROVIDER == "openai" and has_openai:
        active = "openai"
    elif settings.MODEL_PROVIDER == "gemini" and has_gemini:
        active = "gemini"
    elif has_openai:
        active = "openai"
    elif has_gemini:
        active = "gemini"

    return HealthResponse(
        status="ok",
        version="1.0.0",
        timestamp=datetime.now(timezone.utc).isoformat(),
        openai_configured=has_openai,
        gemini_configured=has_gemini,
        active_provider=active
    )


@router.post("/test-key", response_model=TestKeyResponse)
async def test_key_endpoint(request: TestKeyRequest):
    """Tests an OpenAI or Gemini API key live against provider servers."""
    result = await test_llm_api_key(request.api_key, request.provider)
    return TestKeyResponse(
        valid=result.get("valid", False),
        provider=result.get("provider", request.provider),
        model=result.get("model", "unknown"),
        message=result.get("message", ""),
        error=result.get("error")
    )


@router.post("/audit", response_model=AuditResponse)
async def audit_code(request: AuditRequest):
    """
    Audits a source code snippet:
    1. Extracts AST metadata, syntax validity, function/class declarations, and complexity metrics.
    2. Orchestrates multi-agent analysis (Security Specialist, Performance Specialist, Lead Refactorer).
    3. Produces quality score, findings, refactored code, and unified Git diff.
    """
    if not request.code.strip():
        raise HTTPException(status_code=400, detail="Source code snippet cannot be empty.")

    try:
        # Step 1: AST Extraction
        ast_data_raw = extract_ast_metadata(request.code)
        ast_data = ASTMetadata(**ast_data_raw)

        # Step 2: Multi-agent execution
        audit_result = await execute_code_audit(
            request.code,
            ast_data_raw,
            api_key=request.api_key,
            provider=request.provider
        )

        summary = AuditSummary(**audit_result["summary"])
        findings = [Finding(**f) for f in audit_result.get("findings", [])]

        return AuditResponse(
            summary=summary,
            findings=findings,
            ast_data=ast_data,
            refactored_code=audit_result.get("refactored_code", request.code),
            git_diff=audit_result.get("git_diff", "")
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"An unexpected error occurred during code audit: {str(e)}"
        )
