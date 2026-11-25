// The /device page's check of the code `apm login` printed. Opening it while signed in ties it to this browser's session.
import { z } from "zod";
import "./zod-csp";

export type DeviceLookup = { kind: "pending" } | { kind: "error"; message: string };

export type DeviceFetch = (url: string, init: RequestInit) => Promise<Response>;

const DeviceInfo = z.object({ user_code: z.string(), status: z.string() });

export async function lookupDeviceCode(code: string, fetcher: DeviceFetch = fetch): Promise<DeviceLookup> {
  let res: Response;

  try {
    res = await fetcher(`/api/auth/device?user_code=${encodeURIComponent(code)}`, { credentials: "same-origin" });
  } catch {
    return { kind: "error", message: "Could not reach the registry. Check your connection and try again." };
  }

  const info = DeviceInfo.safeParse(await res.json().catch(() => null));

  if (!res.ok || !info.success) return { kind: "error", message: "That code is not valid or has expired. Run apm login again for a new one." };

  if (info.data.status !== "pending") return { kind: "error", message: "That code was already used. Run apm login again for a new one." };

  return { kind: "pending" };
}
