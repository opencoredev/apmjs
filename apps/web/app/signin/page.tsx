import { Suspense } from "react";
import { SignInView } from "./sign-in-view";

export const metadata = {
  title: "Sign in · apm",
  description: "Sign in to apm with GitHub or Vercel to manage packages, publishing tokens, and AI review requests.",
};

export default function SignInPage() {
  return (
    <div className="flex justify-center pt-4 sm:pt-10">
      <Suspense fallback={<div className="h-64 w-full max-w-md animate-pulse rounded-2xl bg-muted" />}>
        <SignInView />
      </Suspense>
    </div>
  );
}
