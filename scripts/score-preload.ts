// Loaded before every test file of a scored run (scripts/score.ts): calling bun:test's `.only`, on test, it, describe
// or any function derived from them (`test.each(rows)`, `test.if(c)`, `test.skip`), throws instead of focusing the
// run, so the file errors and the score is at least 1 (review of efef668, finding 4, and of a24c6aa, finding 3). The
// gate's inventory refuses `.only` from the source as well.
//
// Reading `.only` does not throw (review of a24c6aa, finding 6): a helper that copies a test function's properties
// gets a function that refuses when it is called. bun keeps the modifiers on one prototype shared by every test and
// suite function, where they cannot be redefined: getters (`only`, `skip`, `concurrent`, ...) and functions called
// with a configuration first (`each`, `if`, `skipIf`, ...). So each function is given its own: `only` the refusing
// one, the other getters and functions the prototype's, with what they give back guarded the same way.
/* oxlint-disable anti-slop/no-reflect-get, anti-slop/no-reflect-apply, anti-slop/no-runtime-typeof, anti-slop/no-unknown-parameters, anti-slop/no-unknown-returns -- this file rewires bun:test's own function objects while the run loads: their modifiers are untyped getters and functions on a native prototype, so they can only be read, called and told apart by reflection */
import * as bun from "bun:test";

const FOCUS = "apm score: .only runs part of the suite, which the score refuses";

const refuse = (): never => {
  throw new Error(FOCUS);
};

/** The prototype every bun:test test and suite function shares, and the modifiers it gives them. */
const shared: unknown = Object.getPrototypeOf(bun.test);

type Modifier = { name: string; kind: "getter" } | { name: string; kind: "factory"; factory: (...args: unknown[]) => unknown };

const modifiers: Modifier[] =
  typeof shared === "object" && shared !== null
    ? Object.getOwnPropertyNames(shared).flatMap((name): Modifier[] => {
        const d = Object.getOwnPropertyDescriptor(shared, name);

        if (typeof d?.get === "function") return [{ name, kind: "getter" }];
        const value: unknown = d?.value;

        return typeof value === "function" ? [{ name, kind: "factory", factory: (...args) => Reflect.apply(value, args[0], args.slice(1)) }] : [];
      })
    : [];

const modifierNames = new Set(modifiers.map((m) => m.name));

/** `.only` as the scored run gives it: a function that refuses whatever it is called with. */
type Focused = (...args: unknown[]) => never;

/** `.only`: a function that throws when called or constructed, and stays itself through any modifier (`.only.each(rows)`). */
const focused: Focused = new Proxy<Focused>(refuse, {
  apply: refuse,
  construct: refuse,
  get: (target, key, receiver): unknown => (typeof key === "string" && modifierNames.has(key) ? focused : Reflect.get(target, key, receiver)),
});

const guarded = new WeakSet<object>();

/** `fn` with its own `.only` that refuses, and its own modifiers, whose results are guarded too. */
function guard(fn: unknown): unknown {
  if (typeof fn !== "function" || guarded.has(fn) || !Object.isExtensible(fn) || typeof shared !== "object" || shared === null) return fn;
  guarded.add(fn);

  for (const m of modifiers) {
    if (m.name === "only") Object.defineProperty(fn, m.name, { value: focused, configurable: true, writable: true });
    else if (m.kind === "getter") Object.defineProperty(fn, m.name, { configurable: true, get: () => guard(Reflect.get(shared, m.name, fn)) });
    // called on `fn` whatever it is called on, so a copy of it works as the original does
    else Object.defineProperty(fn, m.name, { configurable: true, writable: true, value: (...args: unknown[]): unknown => guard(m.factory(fn, ...args)) });
  }

  return fn;
}

// every test and suite function bun:test exports or puts on globalThis (xdescribe, xit, xtest and any later ones too:
// review of 137141c), told apart by the prototype they share
const exported = [...Object.values(bun), ...["test", "it", "describe", "xtest", "xit", "xdescribe"].map((name) => Reflect.get(globalThis, name))];

for (const fn of exported) if (typeof fn === "function" && Object.getPrototypeOf(fn) === shared) guard(fn);
