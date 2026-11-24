import { cn } from "@/lib/utils";

function scoreColor(score: number): string {
  if (score >= 85) return "#10b981";
  if (score >= 65) return "#f59e0b";
  return "#ef4444";
}

export function ScoreGauge({
  score,
  label = "TLS Security Score",
  size = 180,
  className,
  showLabel = true,
}: {
  score: number;
  label?: string;
  size?: number;
  className?: string;
  showLabel?: boolean;
}) {
  const stroke = 12;
  const radius = (size - stroke) / 2;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference * (1 - score / 100);
  const color = scoreColor(score);
  const small = size < 64;

  return (
    <div className={cn("flex flex-col items-center gap-2", className)}>
      <div className="relative" style={{ width: size, height: size }}>
        <svg width={size} height={size} className="-rotate-90">
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            strokeWidth={stroke}
            className="stroke-muted"
          />
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            strokeWidth={stroke}
            stroke={color}
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            style={{ transition: "stroke-dashoffset 0.8s ease" }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span
            className="font-mono font-bold leading-none"
            style={{ color, fontSize: Math.max(8, Math.round(size * 0.28)) }}
          >
            {score}
          </span>
          {!small && (
            <span className="font-mono text-muted-foreground" style={{ fontSize: Math.max(9, size * 0.08) }}>
              / 100
            </span>
          )}
        </div>
      </div>
      {showLabel && !small && <span className="text-sm font-medium text-muted-foreground">{label}</span>}
    </div>
  );
}
