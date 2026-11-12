// Structured logs: one JSON object per line on stdout. Fields are scalars only, so a finding's quote,
// a model summary or any other text from a package cannot end up in the logs by accident.
export type LogValue = string | number | boolean | null;

export type LogFields = { readonly [key: string]: LogValue };

export type Logger = (level: "info" | "warn" | "error", event: string, fields?: LogFields) => void;

export const jsonLogger: Logger = (level, event, fields = {}) => {
  process.stdout.write(`${JSON.stringify({ ts: new Date().toISOString(), level, event, ...fields })}\n`);
};

export const silentLogger: Logger = () => {};
