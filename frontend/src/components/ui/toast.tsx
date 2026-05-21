import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useReducer,
  type ReactNode,
} from "react";
import { CheckCircle2, AlertTriangle, AlertCircle, Info, X } from "lucide-react";
import { cn } from "../../lib/utils";

export type ToastTone = "default" | "success" | "warning" | "error";

export interface Toast {
  id: string;
  title: string;
  description?: string;
  tone?: ToastTone;
  durationMs?: number;
}

type Action =
  | { type: "add"; toast: Toast }
  | { type: "dismiss"; id: string };

function reducer(state: Toast[], action: Action): Toast[] {
  switch (action.type) {
    case "add":
      return [...state, action.toast];
    case "dismiss":
      return state.filter((t) => t.id !== action.id);
  }
}

interface ToastContextValue {
  toast: (t: Omit<Toast, "id">) => string;
  dismiss: (id: string) => void;
}

const ToastContext = createContext<ToastContextValue | null>(null);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, dispatch] = useReducer(reducer, []);

  const dismiss = useCallback((id: string) => {
    dispatch({ type: "dismiss", id });
  }, []);

  const toast = useCallback(
    (t: Omit<Toast, "id">) => {
      const id = `t_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 7)}`;
      dispatch({ type: "add", toast: { id, ...t } });
      return id;
    },
    [],
  );

  const value = useMemo(() => ({ toast, dismiss }), [toast, dismiss]);

  return (
    <ToastContext.Provider value={value}>
      {children}
      <Viewport toasts={toasts} onDismiss={dismiss} />
    </ToastContext.Provider>
  );
}

export function useToast(): ToastContextValue {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error("useToast must be used inside <ToastProvider>");
  return ctx;
}

const TONE_STYLES: Record<ToastTone, { ring: string; icon: ReactNode; iconColor: string }> = {
  default: {
    ring: "border-[hsl(var(--border))]",
    icon: <Info className="h-4 w-4" />,
    iconColor: "text-[hsl(var(--primary))]",
  },
  success: {
    ring: "border-[hsl(var(--success)/0.4)]",
    icon: <CheckCircle2 className="h-4 w-4" />,
    iconColor: "text-[hsl(var(--success))]",
  },
  warning: {
    ring: "border-[hsl(var(--warning)/0.4)]",
    icon: <AlertTriangle className="h-4 w-4" />,
    iconColor: "text-[hsl(var(--warning))]",
  },
  error: {
    ring: "border-[hsl(var(--severity-critical)/0.5)]",
    icon: <AlertCircle className="h-4 w-4" />,
    iconColor: "text-[hsl(var(--severity-critical))]",
  },
};

function Viewport({
  toasts,
  onDismiss,
}: {
  toasts: Toast[];
  onDismiss: (id: string) => void;
}) {
  return (
    <div
      role="region"
      aria-label="Notifications"
      className="pointer-events-none fixed bottom-4 right-4 z-[100] flex w-full max-w-sm flex-col gap-2"
    >
      {toasts.map((t) => (
        <ToastItem key={t.id} toast={t} onDismiss={onDismiss} />
      ))}
    </div>
  );
}

function ToastItem({
  toast,
  onDismiss,
}: {
  toast: Toast;
  onDismiss: (id: string) => void;
}) {
  const tone = toast.tone ?? "default";
  const styles = TONE_STYLES[tone];
  const duration = toast.durationMs ?? 5000;

  useEffect(() => {
    if (duration <= 0) return;
    const timer = window.setTimeout(() => onDismiss(toast.id), duration);
    return () => window.clearTimeout(timer);
  }, [toast.id, duration, onDismiss]);

  return (
    <div
      role="status"
      className={cn(
        "pointer-events-auto flex items-start gap-3 rounded-[var(--radius)] border bg-[hsl(var(--card))] p-3 pr-2 shadow-lg",
        styles.ring,
      )}
    >
      <span className={cn("mt-0.5 shrink-0", styles.iconColor)}>{styles.icon}</span>
      <div className="min-w-0 flex-1">
        <div className="text-sm font-semibold text-[hsl(var(--foreground))]">
          {toast.title}
        </div>
        {toast.description && (
          <div className="mt-0.5 text-xs text-[hsl(var(--muted-foreground))]">
            {toast.description}
          </div>
        )}
      </div>
      <button
        type="button"
        aria-label="Dismiss notification"
        onClick={() => onDismiss(toast.id)}
        className="rounded p-1 text-[hsl(var(--muted-foreground))] transition-colors hover:bg-[hsl(var(--muted))] hover:text-[hsl(var(--foreground))]"
      >
        <X className="h-3.5 w-3.5" />
      </button>
    </div>
  );
}
