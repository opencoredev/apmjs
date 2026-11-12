// Markdown imported as text (the *.md rule in next.config.ts), as app/llms-full.txt/route.ts does.
declare module "*.md" {
  const text: string;
  export default text;
}
