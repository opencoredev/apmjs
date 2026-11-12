// Zod 4 probes for eval support with `Function("")` before its first object parse, to compile faster
// parsers. The site's CSP has no 'unsafe-eval', so in the browser that probe is a CSP violation report
// on every page. jitless skips the probe and the compiled path; parsing results are the same.
// Imported for its side effect by every module that parses with Zod in the browser.
import { z } from "zod";

z.config({ jitless: true });
