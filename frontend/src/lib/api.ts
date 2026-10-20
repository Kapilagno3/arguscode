import axios from "axios";

const getBaseUrl = (): string => {
  const envUrl = process.env.NEXT_PUBLIC_API_URL;
  if (!envUrl) return "/api/v1";
  const clean = envUrl.replace(/\/+$/, "");
  return clean.endsWith("/api/v1") ? clean : `${clean}/api/v1`;
};

const API_BASE_URL = getBaseUrl();

const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
  headers: {
    "Content-Type": "application/json",
  },
});

// Fallback to direct backend URL if proxy fails during local development
apiClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    if (error.config && !error.config._retry && (error.code === "ERR_NETWORK" || !error.response)) {
      error.config._retry = true;
      // Only fallback to localhost if we're in browser and on localhost and no explicit NEXT_PUBLIC_API_URL was set
      if (
        typeof window !== "undefined" &&
        (window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1") &&
        !process.env.NEXT_PUBLIC_API_URL &&
        !error.config.baseURL?.startsWith("http://127.0.0.1:8000")
      ) {
        error.config.baseURL = "http://127.0.0.1:8000/api/v1";
        return apiClient(error.config);
      }
    }
    return Promise.reject(error);
  }
);

export interface Finding {
  type: "security" | "performance" | "style";
  severity: "HIGH" | "MED" | "LOW";
  line: number | null;
  message: string;
  fix: string;
}

export interface FunctionMeta {
  name: string;
  lineno: number;
  args: string[];
  returns: string | null;
  docstring: string | null;
}

export interface ClassMeta {
  name: string;
  lineno: number;
  methods: string[];
  bases: string[];
}

export interface ASTMetadata {
  is_valid_syntax: boolean;
  error: string | null;
  error_line: number | null;
  error_column: number | null;
  functions: FunctionMeta[];
  classes: ClassMeta[];
  imports: string[];
  complexity_score: number;
  lines_of_code: number;
}

export interface AuditSummary {
  quality_score: number;
  verdict: string;
  overview: string;
}

export interface AuditResponse {
  summary: AuditSummary;
  findings: Finding[];
  ast_data: ASTMetadata;
  refactored_code: string;
  git_diff: string;
}

export interface HealthResponse {
  status: string;
  version: string;
  timestamp: string;
  openai_configured?: boolean;
  gemini_configured?: boolean;
  active_provider?: string;
}

export interface TestKeyResponse {
  valid: boolean;
  provider: string;
  model: string;
  message: string;
  error?: string | null;
}

export async function runCodeAudit(
  code: string,
  language: string = "python",
  apiKey?: string,
  provider?: string
): Promise<AuditResponse> {
  const response = await apiClient.post<AuditResponse>("/audit", {
    code,
    language,
    api_key: apiKey || undefined,
    provider: provider || undefined,
  });
  return response.data;
}

export async function checkBackendHealth(): Promise<HealthResponse> {
  const response = await apiClient.get<HealthResponse>("/health");
  return response.data;
}

export async function testLLMApiKey(apiKey: string, provider: string): Promise<TestKeyResponse> {
  const response = await apiClient.post<TestKeyResponse>("/test-key", {
    api_key: apiKey,
    provider,
  });
  return response.data;
}
