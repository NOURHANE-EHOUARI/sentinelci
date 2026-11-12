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
