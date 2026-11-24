"use client";

import { Check, Circle, Loader2, X } from "lucide-react";
import { Progress } from "@/components/ui/progress";
import { cn } from "@/lib/utils";
import type { ScanProgressStep } from "@/types/scan";

export function ScanProgressTerminal({
  steps,
  progress,
  status,
}: {
  steps: ScanProgressStep[];
  progress?: number;
  status?: string;
}) {
  const doneCount = steps.filter((s) => s.state === "done" || s.state === "error").length;
  const percent = progress ?? (steps.length ? (doneCount / steps.length) * 100 : 0);

  return (
    <div className="overflow-hidden rounded-lg border bg-zinc-950 text-zinc-200 dark:bg-black">
      <div className="flex items-center justify-between border-b border-zinc-800 px-4 py-2">
        <span className="font-mono text-xs text-zinc-400">cipherlens-scan — live session</span>
        <span className="font-mono text-xs text-zinc-400">
          {progress !== undefined ? `${Math.round(percent)}%` : `${doneCount}/${steps.length}`}
          {status ? ` · ${status}` : ""}
        </span>
      </div>
      <div className="space-y-0 py-2">
        {steps.map((step) => (
          <div key={step.label} className="flex items-start gap-3 px-4 py-1.5">
            <span className="mt-0.5 shrink-0">
              {step.state === "done" && <Check className="h-3.5 w-3.5 text-emerald-400" />}
              {step.state === "error" && <X className="h-3.5 w-3.5 text-red-400" />}
              {step.state === "running" && <Loader2 className="h-3.5 w-3.5 animate-spin text-sky-400" />}
              {step.state === "pending" && <Circle className="h-3.5 w-3.5 text-zinc-700" />}
            </span>
            <div className="min-w-0">
              <p
                className={cn(
                  "font-mono text-xs",
                  step.state === "running" && "text-sky-300",
                  step.state === "done" && "text-emerald-300",
                  step.state === "error" && "text-red-400",
                  step.state === "pending" && "text-zinc-600",
                )}
              >
                {step.state === "running" ? "> " : ""}
                {step.label}
                {step.state === "running" ? "..." : ""}
              </p>
              {step.state === "running" && (
                <p className="font-mono text-[11px] text-zinc-500">{step.detail}</p>
              )}
            </div>
          </div>
        ))}
      </div>
      <div className="px-4 pb-3">
        <Progress value={percent} className="h-1" />
      </div>
    </div>
  );
}
