// Review of efef668, finding 3: settings and whether real npm and pnpm 10 leave a project's devDependency out with
// them. groups.test.ts holds apm's reading to this table; real-layouts.test.ts holds the table to real npm and pnpm
// installs, so the expected answers are what the package managers do, not what apm assumes.
//
// `npm` is what npm 9.3 and later do (checked with 9.3.1, 9.9.4, 10.9.3 and 11.16.0), `npm92` what npm 9.2 does
// (upstream's and Debian's) where it differs: 9.2 type-checks values before it reads them (review of a24c6aa, finding 2).

type Answer = "omit" | "include";

/**
 * `npmrc`: the project's .npmrc. `user`: the user's (~/.npmrc). `global`: a file npm_config_globalconfig names.
 * `env`: the environment of the install.
 */
export type OmissionCase = { name: string; npmrc?: string; user?: string; global?: string; env?: Record<string, string>; npm: Answer; npm92?: Answer; pnpm: Answer };

/** The table's answer for an npm of `version` (major, minor). */
export const npmAnswer = (c: OmissionCase, version: { major: number; minor: number }): Answer => (version.major < 9 || (version.major === 9 && version.minor < 3) ? (c.npm92 ?? c.npm) : c.npm);

export const OMISSION_CASES: readonly OmissionCase[] = [
  { name: "nothing set", npm: "include", pnpm: "include" },
  { name: "omit=dev", npmrc: "omit=dev\n", npm: "omit", pnpm: "include" },
  { name: 'omit="dev" (double quotes)', npmrc: 'omit="dev"\n', npm: "omit", pnpm: "include" },
  { name: "omit='dev' (single quotes)", npmrc: "omit='dev'\n", npm: "omit", pnpm: "include" },
  { name: "omit=dev ; a comment", npmrc: "omit=dev ; c\n", npm: "omit", pnpm: "include" },
  { name: 'omit="dev" # a comment after the quotes', npmrc: 'omit="dev" # c\n', npm: "include", pnpm: "include" },
  { name: "  omit = dev  (spaces)", npmrc: "  omit = dev  \n", npm: "omit", pnpm: "include" },
  { name: "omit=dev,optional (not a list to npm)", npmrc: "omit=dev,optional\n", npm: "include", pnpm: "include" },
  { name: "omit=optional dev (not a list to npm)", npmrc: "omit=optional dev\n", npm: "include", pnpm: "include" },
  { name: "omit[]=optional, omit[]=dev", npmrc: "omit[]=optional\nomit[]=dev\n", npm: "omit", pnpm: "include" },
  { name: "omit=dev, then omit=optional", npmrc: "omit=dev\nomit=optional\n", npm: "include", pnpm: "include" },
  { name: "omit=dev under a [section]", npmrc: "[x]\nomit=dev\n", npm: "include", pnpm: "include" },
  { name: "OMIT=dev (keys are case-sensitive in a file)", npmrc: "OMIT=dev\n", npm: "include", pnpm: "include" },
  { name: "omit=${OM} with OM=dev", npmrc: "omit=${OM}\n", env: { OM: "dev" }, npm: "omit", pnpm: "include" },
  { name: "an empty omit= beats NODE_ENV=production", npmrc: "omit=\n", env: { NODE_ENV: "production" }, npm: "include", pnpm: "include" },
  { name: "omit=bogus beats NODE_ENV=production", npmrc: "omit=bogus\n", env: { NODE_ENV: "production" }, npm: "include", pnpm: "include" },
  { name: "npm_config_omit=dev", env: { npm_config_omit: "dev" }, npm: "omit", pnpm: "include" },
  { name: "NPM_CONFIG_OMIT=dev", env: { NPM_CONFIG_OMIT: "dev" }, npm: "omit", pnpm: "include" },
  { name: "npm_config_omit='optional dev'", env: { npm_config_omit: "optional dev" }, npm: "include", pnpm: "include" },
  { name: "npm_config_omit=peer and NODE_ENV=production", env: { npm_config_omit: "peer", NODE_ENV: "production" }, npm: "include", pnpm: "include" },
  { name: "npm_config_omit=optional beats the project's omit=dev", env: { npm_config_omit: "optional" }, npmrc: "omit=dev\n", npm: "include", pnpm: "include" },
  { name: "npm_config_only=production", env: { npm_config_only: "production" }, npm: "omit", pnpm: "omit" },
  { name: "npm_config_only=prod", env: { npm_config_only: "prod" }, npm: "omit", pnpm: "omit" },
  { name: "only=prod", npmrc: "only=prod\n", npm: "omit", pnpm: "omit" },
  { name: 'only="prod"', npmrc: 'only="prod"\n', npm: "omit", pnpm: "omit" },
  { name: "npm_config_only=dev", env: { npm_config_only: "dev" }, npm: "include", pnpm: "include" },
  { name: "only=bogus, production=true", npmrc: "only=bogus\nproduction=true\n", npm: "omit", pnpm: "include" },
  { name: "only=dev, production=true", npmrc: "only=dev\nproduction=true\n", npm: "omit", pnpm: "include" },
  { name: "npm_config_production=true", env: { npm_config_production: "true" }, npm: "omit", pnpm: "omit" },
  { name: "production=true", npmrc: "production=true\n", npm: "omit", pnpm: "omit" },
  { name: 'production="true"', npmrc: 'production="true"\n', npm: "omit", pnpm: "omit" },
  { name: "production (bare)", npmrc: "production\n", npm: "omit", pnpm: "omit" },
  { name: "production=", npmrc: "production=\n", npm: "omit", pnpm: "omit" },
  { name: 'production=""', npmrc: 'production=""\n', npm: "omit", pnpm: "omit" },
  { name: "production=yes", npmrc: "production=yes\n", npm: "omit", pnpm: "omit" },
  { name: "production=1", npmrc: "production=1\n", npm: "omit", pnpm: "omit" },
  { name: "production=null", npmrc: "production=null\n", npm: "include", pnpm: "include" },
  { name: "production=0 and NODE_ENV=production", npmrc: "production=0\n", env: { NODE_ENV: "production" }, npm: "omit", npm92: "include", pnpm: "omit" },
  { name: "production=${P} with P=true", npmrc: "production=${P}\n", env: { P: "true" }, npm: "omit", pnpm: "omit" },
  { name: "production=${P} with P=false", npmrc: "production=${P}\n", env: { P: "false" }, npm: "omit", npm92: "include", pnpm: "omit" },
  { name: "NODE_ENV=production", env: { NODE_ENV: "production" }, npm: "omit", pnpm: "include" },
  { name: "NODE_ENV=production and npm_config_production=false", env: { NODE_ENV: "production", npm_config_production: "false" }, npm: "include", pnpm: "include" },
  { name: "production=false and omit=dev", npmrc: "production=false\nomit=dev\n", npm: "include", pnpm: "include" },
  { name: "npm_config_production=false beats the project's production=true", env: { npm_config_production: "false" }, npmrc: "production=true\n", npm: "include", pnpm: "include" },
  { name: "the project's production=true, the user's production=false", npmrc: "production=true\n", user: "production=false\n", npm: "include", pnpm: "omit" },
  { name: "npm_config_omit=dev and npm_config_include=dev", env: { npm_config_omit: "dev", npm_config_include: "dev" }, npm: "include", pnpm: "include" },
  { name: "npm_config_omit=dev and the project's include=dev", env: { npm_config_omit: "dev" }, npmrc: "include=dev\n", npm: "include", pnpm: "include" },
  { name: "include=dev and NODE_ENV=production", npmrc: "include=dev\n", env: { NODE_ENV: "production" }, npm: "include", pnpm: "include" },
  { name: "npm_config_also=dev and npm_config_only=prod", env: { npm_config_also: "dev", npm_config_only: "prod" }, npm: "include", pnpm: "omit" },
  { name: "npm_config_dev=true and npm_config_omit=dev", env: { npm_config_dev: "true", npm_config_omit: "dev" }, npm: "include", pnpm: "include" },
  { name: "the user's omit=dev", user: "omit=dev\n", npm: "omit", pnpm: "include" },
  { name: "the user's omit=dev, the project's omit=optional", user: "omit=dev\n", npmrc: "omit=optional\n", npm: "include", pnpm: "include" },
  { name: "the user's production=true", user: "production=true\n", npm: "omit", pnpm: "omit" },
  { name: "a global config's omit=dev and production=true", global: "omit=dev\nproduction=true\n", npm: "omit", pnpm: "omit" },
  { name: "pnpm_config_production=true (pnpm 10 reads npm_config_ only)", env: { pnpm_config_production: "true" }, npm: "include", pnpm: "include" },
  // review of a24c6aa, finding 2: `key[]=` lists of settings that are not lists (npm 9 and 11 agree on each)
  { name: "production[]=false, production[]=true", npmrc: "production[]=false\nproduction[]=true\n", npm: "omit", pnpm: "omit" },
  { name: "production[]=false (a list is true)", npmrc: "production[]=false\n", npm: "omit", pnpm: "omit" },
  { name: "production=true, then production[]=false", npmrc: "production=true\nproduction[]=false\n", npm: "omit", pnpm: "omit" },
  { name: "only[]=prod", npmrc: "only[]=prod\n", npm: "omit", pnpm: "include" },
  { name: "only[]=prod twice (read as prod,prod)", npmrc: "only[]=prod\nonly[]=prod\n", npm: "include", pnpm: "include" },
  { name: "only[]=prod, only[]=bogus (9.2 drops bogus)", npmrc: "only[]=prod\nonly[]=bogus\n", npm: "include", npm92: "omit", pnpm: "include" },
  { name: "only[]=true, only[]=prod (9.2 drops true)", npmrc: "only[]=true\nonly[]=prod\n", npm: "include", npm92: "omit", pnpm: "include" },
  { name: "production=0 (the text 0 is true from npm 9.3)", npmrc: "production=0\n", npm: "omit", npm92: "include", pnpm: "omit" },
  { name: "dev=0 and omit=dev (dev=0 is true to every npm)", npmrc: "dev=0\nomit=dev\n", npm: "include", pnpm: "include" },
  { name: "production=undefined over the user's production=true", user: "production=true\n", npmrc: "production=undefined\n", npm: "omit", npm92: "include", pnpm: "include" },
  { name: "only[]=prod, only[]=false (false kept as null)", npmrc: "only[]=prod\nonly[]=false\n", npm: "include", pnpm: "include" },
  { name: "dev[]=false and production=true (a list is true)", npmrc: "dev[]=false\nproduction=true\n", npm: "include", pnpm: "omit" },
  { name: "also[]=dev and production=true", npmrc: "also[]=dev\nproduction=true\n", npm: "include", pnpm: "omit" },
  { name: "also[]=null, also[]=dev and production=true", npmrc: "also[]=null\nalso[]=dev\nproduction=true\n", npm: "omit", pnpm: "omit" },
  { name: "omit=dev and optional[]=false", npmrc: "omit=dev\noptional[]=false\n", npm: "omit", pnpm: "include" },
];
