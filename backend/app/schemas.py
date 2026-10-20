from typing import List, Optional, Literal
from pydantic import BaseModel, Field


class AuditRequest(BaseModel):
    code: str = Field(..., description="Source code snippet to audit")
    language: str = Field(default="python", description="Programming language of the snippet")
    api_key: Optional[str] = Field(default=None, description="Optional user-provided OpenAI or Gemini API Key")
    provider: Optional[str] = Field(default=None, description="Preferred provider: auto, openai, gemini, or heuristic")


class Finding(BaseModel):
    type: Literal["security", "performance", "style"] = Field(..., description="Category of finding")
    severity: Literal["HIGH", "MED", "LOW"] = Field(..., description="Severity level")
    line: Optional[int] = Field(default=None, description="Line number in source code")
    message: str = Field(..., description="Detailed description of the issue")
    fix: str = Field(..., description="Recommended fix or code correction")


class FunctionMetadata(BaseModel):
    name: str
    lineno: int
    args: List[str] = Field(default_factory=list)
    returns: Optional[str] = None
    docstring: Optional[str] = None


class ClassMetadata(BaseModel):
    name: str
    lineno: int
    methods: List[str] = Field(default_factory=list)
    bases: List[str] = Field(default_factory=list)


class ASTMetadata(BaseModel):
    is_valid_syntax: bool = True
    error: Optional[str] = None
    error_line: Optional[int] = None
    error_column: Optional[int] = None
    functions: List[FunctionMetadata] = Field(default_factory=list)
    classes: List[ClassMetadata] = Field(default_factory=list)
    imports: List[str] = Field(default_factory=list)
    complexity_score: int = Field(default=1, description="Branch complexity estimation")
    lines_of_code: int = Field(default=0, description="Total lines of code")


class AuditSummary(BaseModel):
    quality_score: int = Field(..., ge=0, le=100, description="Quality and health score from 0 to 100")
    verdict: str = Field(..., description="Risk verdict e.g. CRITICAL, HIGH RISK, MODERATE, CLEAN")
    overview: str = Field(..., description="Executive summary of the multi-agent findings")


class AuditResponse(BaseModel):
    summary: AuditSummary
    findings: List[Finding] = Field(default_factory=list)
    ast_data: ASTMetadata
    refactored_code: str
    git_diff: str


class HealthResponse(BaseModel):
    status: str = "ok"
    version: str = "1.0.0"
    timestamp: str
    openai_configured: bool = False
    gemini_configured: bool = False
    active_provider: str = "heuristic"


class TestKeyRequest(BaseModel):
    api_key: str = Field(..., description="API key to test")
    provider: str = Field(default="openai", description="Provider: openai or gemini")


class TestKeyResponse(BaseModel):
    valid: bool
    provider: str
    model: str
    message: str
    error: Optional[str] = None
