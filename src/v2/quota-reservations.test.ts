import assert from "node:assert/strict";
import test from "node:test";
import { SynchronousQuotaReservations } from "./quota-reservations.js";

test("quota reservations reject synchronously before committed creation", () => {
  const quota = new SynchronousQuotaReservations("context", { entries: 1 });
  const first = quota.reserve({ entries: 0 }, { entries: 1 });
  let created = 0;
  assert.throws(
    () => quota.reserve({ entries: created }, { entries: 1 }),
    hasCode("RESOURCE_QUOTA_EXCEEDED"),
  );
  assert.equal(created, 0);
  first.commit(() => { created += 1; });
  assert.deepEqual(quota.pending(), { entries: 0 });
  assert.throws(
    () => quota.reserve({ entries: created }, { entries: 1 }),
    hasCode("RESOURCE_QUOTA_EXCEEDED"),
  );
});

test("multi-dimensional reservations are atomic and release is idempotent", () => {
  const quota = new SynchronousQuotaReservations("text", {
    entries: 2,
    characters: 10,
  });
  const reservation = quota.reserve(
    { entries: 1, characters: 4 },
    { entries: 1, characters: 6 },
  );
  assert.deepEqual(quota.pending(), { entries: 1, characters: 6 });
  reservation.release();
  reservation.release();
  assert.equal(reservation.settled, true);
  assert.deepEqual(quota.pending(), { entries: 0, characters: 0 });
});

function hasCode(code: string) {
  return (error: unknown) => error instanceof Error
    && "code" in error
    && error.code === code;
}
