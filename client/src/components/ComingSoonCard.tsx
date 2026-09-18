"use client";

import { useExtracted } from "next-intl";
import { Card, CardContent } from "./ui/card";

/**
 * A placeholder for a feature that exists in the codebase but is not served by
 * this deployment's backend yet, so the dashboard shows where it will appear
 * instead of hiding it.
 */
export function ComingSoonCard({ title, description }: { title: string; description?: string }) {
  const t = useExtracted();

  return (
    <Card className="h-[405px]">
      <CardContent className="flex h-full flex-col items-center justify-center gap-2 text-center">
        <div className="text-sm font-medium text-neutral-900 dark:text-white">{title}</div>
        {description && <div className="max-w-xs text-sm text-neutral-500 dark:text-neutral-400">{description}</div>}
        <div className="mt-1 rounded border border-neutral-200 px-2 py-0.5 text-xs text-neutral-500 dark:border-neutral-800 dark:text-neutral-400">
          {t("Coming soon")}
        </div>
      </CardContent>
    </Card>
  );
}
