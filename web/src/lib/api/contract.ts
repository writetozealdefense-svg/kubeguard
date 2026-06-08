/**
 * Compile-time gate: the zod-inferred contract types (which the UI uses) must be
 * assignable to the OpenAPI-generated `schema.ts` types (which are derived from
 * the Go `pkg/api`). If the backend contract drifts from `pkg/api`, `tsc -b`
 * (run by `npm run build`) fails here. Regenerate with `npm run gen:api`.
 */
import type { components } from "./schema";
import type {
  AttackPath,
  Cluster,
  Finding,
  FrameworkResult,
  PostureSummary,
  Scan,
} from "./types";

type Schema = components["schemas"];

// Sub must be assignable to Sup — both type params are referenced, so the
// assertion fails to compile if a zod type drifts from its OpenAPI counterpart.
type AssertAssignable<Sup, Sub extends Sup> = Sub;

export type _Finding = AssertAssignable<Schema["Finding"], Finding>;
export type _Cluster = AssertAssignable<Schema["Cluster"], Cluster>;
export type _Scan = AssertAssignable<Schema["Scan"], Scan>;
export type _Posture = AssertAssignable<Schema["PostureSummary"], PostureSummary>;
export type _Framework = AssertAssignable<Schema["FrameworkResult"], FrameworkResult>;
export type _AttackPath = AssertAssignable<Schema["AttackPath"], AttackPath>;
