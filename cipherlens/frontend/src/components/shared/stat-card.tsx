import { Card, CardContent } from "@/components/ui/card";
import { cn } from "@/lib/utils";

const ACCENTS = {
  default: "text-foreground",
  emerald: "text-emerald-400",
  amber: "text-amber-400",
  red: "text-red-400",
  sky: "text-sky-400",
  violet: "text-violet-400",
};

export type StatAccent = keyof typeof ACCENTS;

export function StatCard({
  label,
  value,
  icon,
  accent = "default",
  sub,
  onClick,
}: {
  label: string;
  value: string | number;
  icon?: React.ReactNode;
  accent?: StatAccent;
  sub?: string;
  onClick?: () => void;
}) {
  return (
    <Card
      className={cn("relative overflow-hidden", onClick && "cursor-pointer transition-colors hover:border-primary/40")}
      onClick={onClick}
    >
      <CardContent className="p-5">
        <div className="flex items-start justify-between gap-2">
          <div className="min-w-0">
            <p className="truncate text-xs font-medium uppercase tracking-wide text-muted-foreground">{label}</p>
            <p className={cn("mt-2 font-mono text-[27px] leading-none font-bold", ACCENTS[accent])}>{value}</p>
            {sub && <p className="mt-1 truncate text-xs text-muted-foreground">{sub}</p>}
          </div>
          {icon && (
            <div className={"grid size-[34px] shrink-0 place-items-center bg-[var(--accent-soft)] text-[var(--accent-bright)]"}>{icon}</div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
