"use client";

import { useSearchParams } from "next/navigation";
import { SignInPanel } from "@/components/sign-in-panel";
import { safeNext } from "@/lib/safe-next";

export function SignInView() {
  const params = useSearchParams();
  const failed = params.get("error") !== null;

  return (
    <div className="flex w-full max-w-md flex-col gap-4">
      {failed && (
        <p role="alert" className="rounded-lg bg-bad-soft px-4 py-3 text-sm text-bad">
          Sign-in did not finish. Try again.
        </p>
      )}
      <SignInPanel next={safeNext(params.get("next"))} />
    </div>
  );
}
