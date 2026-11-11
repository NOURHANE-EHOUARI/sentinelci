// The root-cause group of a finding in a run's correlation (Correlation v1, A7). Advisory: the gate never reads
// it, and a group labelled by a model is said to be so.

export interface GroupView {
  groupId: string;
  title: string;
  rootCause: string;
  singleFix: string | null;
  stage: string;
  labelledBy: "template" | "llm";
  members: number;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** The group that holds `findingId` in a Correlation v1 document, or null. */
export function groupOf(document: unknown, findingId: string): GroupView | null {
  if (!isRecord(document) || !Array.isArray(document.groups)) return null;
  for (const group of document.groups) {
    if (!isRecord(group) || !Array.isArray(group.finding_ids) || !group.finding_ids.includes(findingId)) continue;
    if (typeof group.title !== "string" || typeof group.root_cause !== "string") return null;
    return {
      groupId: typeof group.group_id === "string" ? group.group_id : "",
      title: group.title,
      rootCause: group.root_cause,
      singleFix: typeof group.single_fix === "string" ? group.single_fix : null,
      stage: typeof group.stage === "string" ? group.stage : "",
      labelledBy: group.labelled_by === "llm" ? "llm" : "template",
      members: group.finding_ids.length,
    };
  }
  return null;
}

export interface RunGroupView extends GroupView {
  findingIds: string[];
  model: string | null;
}

export interface CorrelationView {
  version: string;
  stages: string[];
  groups: RunGroupView[];
}

/** Every group of a Correlation v1 document, largest first, read field by field (a group without a title or a
 * root cause is left out, never shown half-read); null when the document is not one. */
export function correlationOf(document: unknown): CorrelationView | null {
  if (!isRecord(document) || !Array.isArray(document.groups)) return null;
  const correlator = isRecord(document.correlator) ? document.correlator : {};
  const groups: RunGroupView[] = [];
  for (const group of document.groups) {
    if (!isRecord(group) || !Array.isArray(group.finding_ids)) continue;
    if (typeof group.title !== "string" || typeof group.root_cause !== "string") continue;
    const findingIds = group.finding_ids.filter((id): id is string => typeof id === "string");
    groups.push({
      groupId: typeof group.group_id === "string" ? group.group_id : "",
      title: group.title,
      rootCause: group.root_cause,
      singleFix: typeof group.single_fix === "string" ? group.single_fix : null,
      stage: typeof group.stage === "string" ? group.stage : "",
      labelledBy: group.labelled_by === "llm" ? "llm" : "template",
      members: findingIds.length,
      findingIds,
      model: typeof group.model === "string" ? group.model : null,
    });
  }
  groups.sort((a, b) => b.members - a.members || a.groupId.localeCompare(b.groupId));
  return {
    version: typeof correlator.version === "string" ? correlator.version : "",
    stages: Array.isArray(correlator.stages) ? correlator.stages.filter((s): s is string => typeof s === "string") : [],
    groups,
  };
}

/** SPEC section 10: alert reduction = 1 − groups ÷ raw findings (null without findings). */
export function alertReduction(groups: number, findings: number): number | null {
  return findings > 0 ? 1 - groups / findings : null;
}
