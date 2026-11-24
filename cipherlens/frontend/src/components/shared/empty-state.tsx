import { cn } from "@/lib/utils";

export function EmptyState({
  icon,
  title,
  description,
  className,
}: {
  icon?: React.ReactNode;
  title: string;
  description?: string;
  className?: string;
}) {
  return (
    <div className={cn("flex flex-col items-center justify-center gap-2 py-12 text-center", className)}>
      {icon && <div className="text-muted-foreground">{icon}</div>}
      <p className="text-sm font-medium text-foreground">{title}</p>
      {description && <p className="max-w-sm text-xs text-muted-foreground">{description}</p>}
    </div>
  );
}

export function ErrorState({
  message,
  onRetry,
  className,
}: {
  message?: string;
  onRetry?: () => void;
  className?: string;
}) {
  return (
    <div className={cn("flex flex-col items-center justify-center gap-3 py-12 text-center", className)}>
      <p className="text-sm font-medium text-red-400">{message ?? "Something went wrong loading the data."}</p>
      {onRetry && (
        <button onClick={onRetry} className="text-xs text-sky-400 underline underline-offset-4 hover:text-sky-300">
          Retry
        </button>
      )}
    </div>
  );
}
