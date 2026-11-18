// Databuddy's client id goes to production alone (analytics.ts): staging builds render no tracker and staging Workers
// report no errors, so test traffic never reaches production's analytics.
import { describe, expect, test } from "bun:test";
import { DATABUDDY_CLIENT_ID, databuddyBuildEnv, databuddyWorkerEnv } from "../analytics.ts";

describe("Databuddy per stage", () => {
  test("production's builds and Workers get the client id", () => {
    expect(databuddyBuildEnv("production")).toEqual({ NEXT_PUBLIC_DATABUDDY_CLIENT_ID: DATABUDDY_CLIENT_ID });
    expect(databuddyWorkerEnv("production")).toEqual({ APM_DATABUDDY_CLIENT_ID: DATABUDDY_CLIENT_ID });
  });

  test("any other stage gets none: an empty build value and no Worker binding", () => {
    for (const stage of ["staging", "preview", ""]) {
      expect(databuddyBuildEnv(stage)).toEqual({ NEXT_PUBLIC_DATABUDDY_CLIENT_ID: "" });
      expect(databuddyWorkerEnv(stage)).toEqual({});
    }
  });
});
