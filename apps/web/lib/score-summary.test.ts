// The phone's one-line score summary names the signal that cost the most.
import { describe, expect, test } from "bun:test";
import type { Signal } from "./registry";
import { scoreLine, scoreLineText, shortLabel } from "./score-summary";

const signal = (s: Partial<Signal> & Pick<Signal, "id" | "label" | "points">): Signal => ({ evidence: [], confidence: "confirmed", ...s });

const installScript = signal({ id: "install-script", label: "Runs a script at install time (preinstall, install or postinstall)", points: -15 });
const evalSignal = signal({ id: "eval", label: "Evaluates code built at runtime (eval, Function, vm)", points: -10 });
const network = signal({ id: "network", label: "Uses the network: fetch, http, sockets, or a module that makes requests", points: -10 });
const possibleNetwork = signal({ id: "network", label: "Possible network use: names a request or download, but apm did not see one made", points: -5, confidence: "possible" });

describe("scoreLineText", () => {
  test("one signal is named with its points", () => {
    expect(scoreLineText(scoreLine([installScript]))).toBe("Runs a script at install time · −15 points");
    expect(scoreLineText(scoreLine([evalSignal]))).toBe("Evaluates code built at runtime · −10 points");
    expect(scoreLineText(scoreLine([network]))).toBe("Uses the network · −10 points");
  });

  test("several: the biggest is named and the rest counted", () => {
    expect(scoreLineText(scoreLine([evalSignal, installScript, network]))).toBe("Runs a script at install time · −15 points +2 more");
  });

  test("a possible signal reads as possible", () => {
    expect(scoreLineText(scoreLine([possibleNetwork]))).toBe("Possible network use · −5 points");
    expect(scoreLine([possibleNetwork])).toMatchObject({ kind: "lost", possible: true });
    expect(scoreLineText(scoreLine([signal({ id: "eval", label: "Keeps a way to run code", points: -4, confidence: "possible" })]))).toBe("Possible: Keeps a way to run code · −4 points");
  });

  test("a confirmed signal is named before a possible one of the same size", () => {
    const possibleEval = signal({ id: "eval", label: "Possible eval: keeps a way to run code built at runtime", points: -10, confidence: "possible" });

    expect(scoreLineText(scoreLine([possibleEval, network]))).toBe("Uses the network · −10 points +1 more");
  });

  test("notes worth 0 points don't count, and no signals reads as no points lost", () => {
    expect(scoreLineText(scoreLine([signal({ id: "recent", label: "Published less than 24 hours ago; most…", points: 0 })]))).toBe("No points lost");
    expect(scoreLineText(scoreLine([]))).toBe("No points lost");
    expect(scoreLineText(scoreLine(null))).toBe("Not scored yet");
  });
});

test("shortLabel stops at the first explanation", () => {
  expect(shortLabel("Published less than 24 hours ago; most malicious versions are caught within hours")).toBe("Published less than 24 hours ago");
  expect(shortLabel("Starts shell commands or child processes, or loads child_process")).toBe("Starts shell commands or child processes");
  expect(shortLabel("Contains obfuscated code")).toBe("Contains obfuscated code");
});
