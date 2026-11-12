import { describe, expect, it } from "vitest";
import { expiry } from "./rules";

describe("expiry", () => {
  const now = Date.parse("2026-11-20T12:00:00Z");
  const day = 24 * 60 * 60 * 1000;

  it("reads only an RFC 3339 date-time, never guesses a date", () => {
    for (const text of [null, "2026-12-31", "31/12/2026", "2026-12-31 00:00:00Z", "2026-12-31T00:00:00", "soon"]) {
      expect(expiry(text, now)).toEqual({ kind: "unreadable" });
    }
  });

  it("is expired at the instant itself and after it, in whole days", () => {
    expect(expiry("2026-11-20T12:00:00Z", now)).toMatchObject({ kind: "expired", days: 0 });
    expect(expiry("2026-11-17T11:00:00Z", now)).toMatchObject({ kind: "expired", days: 3 });
  });

  it("is expiring soon within 14 days, later from then", () => {
    expect(expiry(new Date(now + 14 * day - 1).toISOString(), now)).toMatchObject({ kind: "soon", days: 13 });
    expect(expiry(new Date(now + 14 * day).toISOString(), now)).toMatchObject({ kind: "later", days: 14 });
    expect(expiry("2026-11-20T12:00:01Z", now)).toMatchObject({ kind: "soon", days: 0 });
  });

  it("keeps the offset the reviewer wrote", () => {
    const state = expiry("2026-12-01T00:00:00+01:00", now);
    expect(state.kind !== "unreadable" && state.at.toISOString()).toBe("2026-11-30T23:00:00.000Z");
  });
});
