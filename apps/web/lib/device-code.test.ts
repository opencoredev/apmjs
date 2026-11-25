// The /device page must always leave its loading state: a lookup that cannot reach the registry is an error to show.
import { describe, expect, test } from "bun:test";
import { lookupDeviceCode, type DeviceFetch } from "./device-code";

type DeviceAnswer = { user_code?: string; status?: string; error?: string };

const answering =
  (body: DeviceAnswer, status = 200): DeviceFetch =>
  async () =>
    Response.json(body, { status });

describe("lookupDeviceCode", () => {
  test("a pending code can be approved", async () => {
    expect(await lookupDeviceCode("ABCDEFGH", answering({ user_code: "ABCDEFGH", status: "pending" }))).toEqual({ kind: "pending" });
  });

  test("a network failure is an error, not a rejected promise", async () => {
    const offline: DeviceFetch = async () => {
      throw new TypeError("Failed to fetch");
    };

    expect(await lookupDeviceCode("ABCDEFGH", offline)).toEqual({ kind: "error", message: "Could not reach the registry. Check your connection and try again." });
  });

  test("unknown, expired and used codes say so", async () => {
    const html: DeviceFetch = async () => new Response("<html>", { status: 502 });

    expect(await lookupDeviceCode("ABCDEFGH", answering({ error: "invalid_grant" }, 400))).toMatchObject({ kind: "error", message: expect.stringContaining("not valid or has expired") });
    expect(await lookupDeviceCode("ABCDEFGH", html)).toMatchObject({ kind: "error" });
    expect(await lookupDeviceCode("ABCDEFGH", answering({ user_code: "ABCDEFGH", status: "approved" }))).toMatchObject({ kind: "error", message: expect.stringContaining("already used") });
  });

  test("the code is encoded into the query", async () => {
    let asked = "";

    const spy: DeviceFetch = async (url) => {
      asked = url;

      return Response.json({ user_code: "x", status: "pending" });
    };

    await lookupDeviceCode("AB&C", spy);
    expect(asked).toBe("/api/auth/device?user_code=AB%26C");
  });
});
