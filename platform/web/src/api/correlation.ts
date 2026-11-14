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
  /** The model that wrote the labels, as Root-cause group v1 names it (`provider name`), or null. */
  model: string | null;
}

export interface CorrelationView {
  version: string;
  stages: string[];
  groups: RunGroupView[];
  /** How many groups of the document could not be read and were left out. */
  unread: number;
}

/** Root-cause group v1's `model` is an object: its provider and name say which model wrote the labels. */
function modelOf(model: unknown): string | null {
  if (!isRecord(model) || typeof model.name !== "string") return null;
  return typeof model.provider === "string" ? `${model.provider} ${model.name}` : model.name;
}

/** Every group of a Correlation v1 document, largest first, read field by field (a group without a title or a
 * root cause is left out, never shown half-read); null when the document is not one. */
export function correlationOf(document: unknown): CorrelationView | null {
  if (!isRecord(document) || !Array.isArray(document.groups)) return null;
  const correlator = isRecord(document.correlator) ? document.correlator : {};
  const groups: RunGroupView[] = [];
  let unread = 0;
  for (const group of document.groups) {
    if (
      !isRecord(group) || !Array.isArray(group.finding_ids) || typeof group.title !== "string" ||
      typeof group.root_cause !== "string"
    ) {
      unread += 1;
      continue;
    }
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
      model: modelOf(group.model),
    });
  }
  groups.sort((a, b) => b.members - a.members || a.groupId.localeCompare(b.groupId));
  return {
    version: typeof correlator.version === "string" ? correlator.version : "",
    stages: Array.isArray(correlator.stages) ? correlator.stages.filter((s): s is string => typeof s === "string") : [],
    groups,
    unread,
  };
}

/** SPEC section 10: alert reduction = 1 − groups ÷ raw findings (null without findings). */
export function alertReduction(groups: number, findings: number): number | null {
  return findings > 0 ? 1 - groups / findings : null;
}
