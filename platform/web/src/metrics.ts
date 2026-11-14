// `sentinel_findings_open{priority,category}` from GET /metrics (SPEC section 10). The metric is absent until a
// release run of the default branch is recorded: then there is no data, which is not the same as zero.

export interface OpenFindings {
  priority: string;
  category: string;
  value: number;
}

const SAMPLE = /^sentinel_findings_open\{([^}]*)\} (\S+)$/;
const LABEL = /^([a-z_]+)="((?:[^"\\]|\\.)*)"$/;

/** Every sample of sentinel_findings_open, or null when the metric is absent. */
export function openFindings(exposition: string): OpenFindings[] | null {
  const samples: OpenFindings[] = [];
  for (const line of exposition.split("\n")) {
    const match = SAMPLE.exec(line);
    if (!match) continue;
    const labels: Record<string, string> = {};
    for (const pair of (match[1] ?? "").split(",")) {
      const label = LABEL.exec(pair);
      if (label?.[1] !== undefined && label[2] !== undefined) labels[label[1]] = label[2];
    }
    const value = Number(match[2]);
    if (labels.priority === undefined || labels.category === undefined || !Number.isFinite(value)) continue;
    samples.push({ priority: labels.priority, category: labels.category, value });
  }
  return samples.length ? samples : null;
}

export function totalBy(samples: OpenFindings[], key: "priority" | "category"): Map<string, number> {
  const totals = new Map<string, number>();
  for (const sample of samples) totals.set(sample[key], (totals.get(sample[key]) ?? 0) + sample.value);
  return totals;
}

export interface RemediationCount {
  strategy: string;
  outcome: string;
  value: number;
}

const ATTEMPT = /^sentinel_remediation_attempts_total\{strategy="([^"\\]*)",outcome="([^"\\]*)"\} (\S+)$/;

/** Every sample of sentinel_remediation_attempts_total, or null when the metric is absent. */
export function remediationAttempts(exposition: string): RemediationCount[] | null {
  const samples: RemediationCount[] = [];
  for (const line of exposition.split("\n")) {
    const match = ATTEMPT.exec(line);
    const value = Number(match?.[3]);
    if (match?.[1] !== undefined && match[2] !== undefined && Number.isFinite(value)) {
      samples.push({ strategy: match[1], outcome: match[2], value });
    }
  }
  return samples.length ? samples : null;
}

/** SPEC section 10: remediation success = VERIFIED ÷ attempted, per strategy (strategies with attempts). */
export function successByStrategy(samples: RemediationCount[]): Map<string, { verified: number; attempted: number }> {
  const totals = new Map<string, { verified: number; attempted: number }>();
  for (const sample of samples) {
    const total = totals.get(sample.strategy) ?? { verified: 0, attempted: 0 };
    total.attempted += sample.value;
    if (sample.outcome === "VERIFIED") total.verified += sample.value;
    totals.set(sample.strategy, total);
  }
  return new Map([...totals].filter(([, total]) => total.attempted > 0));
}
