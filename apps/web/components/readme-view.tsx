"use client";

import type { ReactNode } from "react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

/** The readme rendered (sanitized on the server) or as the Markdown the publisher wrote, one tab each. */
export function ReadmeView({ rendered, source, note }: { rendered: ReactNode; source: string; note: ReactNode }) {
  return (
    <Tabs defaultValue="rendered" className="gap-0 border-t">
      <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2 border-b px-4 py-2">
        <span className="text-sm text-muted-foreground">{note}</span>
        <TabsList aria-label="Readme view" className="h-8 rounded-full bg-surface p-0.5">
          <TabsTrigger value="rendered" className="h-7 rounded-full px-3 text-[13px] data-active:bg-background data-active:shadow-xs">
            Rendered
          </TabsTrigger>
          <TabsTrigger value="source" className="h-7 rounded-full px-3 text-[13px] data-active:bg-background data-active:shadow-xs">
            View source
          </TabsTrigger>
        </TabsList>
      </div>
      <TabsContent value="rendered" className="readme min-w-0 px-4 py-5 text-[15px] sm:px-6">
        {rendered}
      </TabsContent>
      <TabsContent value="source">
        <pre className="overflow-x-auto bg-surface p-4 font-mono text-[13px] leading-relaxed whitespace-pre-wrap [overflow-wrap:anywhere]">{source}</pre>
      </TabsContent>
    </Tabs>
  );
}
