// The platform API, read only (SPEC section 13.3). The types come from schemas/openapi.yaml (`npm run client`).
import type { components } from "./schema";

export type FindingPage = components["schemas"]["FindingPage"];
export type FindingDetail = components["schemas"]["FindingDetail"];
export type CorrelationVersion = components["schemas"]["CorrelationOut"];
export type RunPage = components["schemas"]["RunPage"];
export type Run = components["schemas"]["RunOut"];

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

type Params = Record<string, string | number | undefined>;

export function apiUrl(path: string, params: Params = {}): string {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== "") query.set(key, String(value));
  }
  const suffix = query.toString();
  return suffix ? `${path}?${suffix}` : path;
}

async function get(path: string, params: Params = {}, accept = "application/json"): Promise<Response> {
  const response = await fetch(apiUrl(path, params), { headers: { Accept: accept } });
  if (!response.ok) {
    throw new ApiError(response.status, `${path} answered ${response.status}`);
  }
  return response;
}

export interface FindingFilters {
  repo?: string | undefined;
  category?: string | undefined;
  severity?: string | undefined;
  tool?: string | undefined;
  run_id?: string | undefined;
  limit?: number | undefined;
  offset?: number | undefined;
}

export async function listFindings(filters: FindingFilters): Promise<FindingPage> {
  return (await get("/api/v1/findings", { ...filters })).json() as Promise<FindingPage>;
}

export async function getFinding(findingId: string): Promise<FindingDetail> {
  return (await get(`/api/v1/findings/${encodeURIComponent(findingId)}`)).json() as Promise<FindingDetail>;
}

export interface RunFilters {
  repo?: string | undefined;
  context?: string | undefined;
  ref?: string | undefined;
  limit?: number | undefined;
  offset?: number | undefined;
}

/** Recorded runs, newest first. */
export async function listRuns(filters: RunFilters): Promise<RunPage> {
  return (await get("/api/v1/runs", { ...filters })).json() as Promise<RunPage>;
}

export async function getRun(runId: string): Promise<Run> {
  return (await get(`/api/v1/runs/${encodeURIComponent(runId)}`)).json() as Promise<Run>;
}

/** The run's gate decision (Decision v1), or null when none is recorded (404): never a PASS by default. */
export async function getDecision(runId: string): Promise<unknown> {
  try {
    return await (await get(`/api/v1/runs/${encodeURIComponent(runId)}/decision`)).json();
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) return null;
    throw error;
  }
}

/** The run's latest correlation document, or null when none is recorded (404). */
export async function getCorrelation(runId: string): Promise<unknown> {
  try {
    return await (await get(`/api/v1/runs/${encodeURIComponent(runId)}/correlations`)).json();
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) return null;
    throw error;
  }
}

/** GET /metrics: Prometheus text. */
export async function getMetrics(): Promise<string> {
  return (await get("/metrics", {}, "text/plain")).text();
}
