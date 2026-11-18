// The platform API, read only (SPEC section 13.3). The types come from schemas/openapi.yaml (`npm run client`).
import type { components, operations } from "./schema";

export type FindingPage = components["schemas"]["FindingPage"];
export type FindingDetail = components["schemas"]["FindingDetail"];
export type CorrelationVersion = components["schemas"]["CorrelationOut"];
export type ReleasePage = components["schemas"]["ReleasePage"];
export type ReleaseSummary = components["schemas"]["ReleaseOut"];
export type RemediationPage = components["schemas"]["RemediationPage"];
export type RemediationSummary = components["schemas"]["RemediationOut"];
export type RunPage = components["schemas"]["RunPage"];
export type WaiversPage = components["schemas"]["WaiversPage"];
export type WaiversInForce = components["schemas"]["WaiversInForce"];
export type Waiver = components["schemas"]["WaiverOut"];
export type RuleCounts = components["schemas"]["RulesOut"];
export type Run = components["schemas"]["RunOut"];
/** The same type, under the name the A8 pages use. */
export type RunSummary = Run;

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

/** For each repository, its latest release decision of the default branch and the waivers it read. */
export async function listWaiversInForce(repo?: string): Promise<WaiversPage> {
  return (await get("/api/v1/waivers", { repo })).json() as Promise<WaiversPage>;
}

/** How many recorded decisions each rule fired in, by effect and context. */
export async function getRuleCounts(): Promise<RuleCounts> {
  return (await get("/api/v1/rules")).json() as Promise<RuleCounts>;
}

type ExplanationResponses = operations["get_explanation_api_v1_findings__finding_id__explanation_get"]["responses"];

/** What `GET /api/v1/findings/{id}/explanation` answers when the finding's latest explanation is not a valid
 * Explanation v1 document about it (T33): it is not served, and nothing older is served in its place. Typed
 * from the contract, so the build fails if schemas/openapi.yaml stops documenting it. Its body is never read. */
export const EXPLANATION_REFUSED: keyof ExplanationResponses & 500 = 500;

/** The finding's latest explanation (Explanation v1, advisory), or null when none is recorded (404). A refused
 * one is an ApiError with status EXPLANATION_REFUSED. */
export async function getExplanation(findingId: string): Promise<unknown> {
  try {
    return await (await get(`/api/v1/findings/${encodeURIComponent(findingId)}/explanation`)).json();
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

export interface ReleaseFilters {
  repo?: string | undefined;
  verdict?: string | undefined;
  limit?: number | undefined;
  offset?: number | undefined;
}

export async function listReleases(filters: ReleaseFilters): Promise<ReleasePage> {
  return (await get("/api/v1/releases", { ...filters })).json() as Promise<ReleasePage>;
}

/** The image's latest release evidence (Release evidence v1), or the one of `decisionId`. */
export async function getReleaseEvidence(imageDigest: string, decisionId?: string): Promise<unknown> {
  const path = `/api/v1/releases/${encodeURIComponent(imageDigest)}/evidence`;
  return (await get(path, { decision_id: decisionId })).json();
}

export interface RemediationFilters {
  strategy?: string | undefined;
  outcome?: string | undefined;
  limit?: number | undefined;
  offset?: number | undefined;
}

export async function listRemediations(filters: RemediationFilters): Promise<RemediationPage> {
  return (await get("/api/v1/remediations", { ...filters })).json() as Promise<RemediationPage>;
}

/** One attempt of the remediation loop (Remediation attempt v1), as recorded. */
export async function getRemediation(proposalId: string): Promise<unknown> {
  return (await get(`/api/v1/remediations/${encodeURIComponent(proposalId)}`)).json();
}
