import { expect, test } from "bun:test";
import { unavailablePage } from "./unavailable-page";

test("the package name and retry path are escaped", () => {
  const html = unavailablePage({ name: `<img src=x onerror=alert(1)>"'`, retryPath: `/package/a"><script>alert(1)</script>` });

  expect(html).not.toContain("<img");
  expect(html).not.toContain("<script>");
  expect(html).toContain("&#60;img src=x onerror=alert(1)&#62;&#34;&#39;");
  expect(html).toContain(`href="/package/a&#34;&#62;&#60;script&#62;alert(1)&#60;/script&#62;"`);
});
