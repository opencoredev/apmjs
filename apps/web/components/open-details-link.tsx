"use client";

/** A jump link to a `<details>` that also opens it, so the reader lands on the content and not on a closed row. */
export function OpenDetailsLink({ target, className, children }: { target: string; className?: string; children: React.ReactNode }) {
  return (
    <a
      href={`#${target}`}
      className={className}
      onClick={() => {
        const el = document.getElementById(target);

        if (el instanceof HTMLDetailsElement) el.open = true;
      }}
    >
      {children}
    </a>
  );
}
