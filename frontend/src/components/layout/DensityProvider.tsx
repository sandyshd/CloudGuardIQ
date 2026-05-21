import { createContext, useContext, useEffect, useMemo, useState } from "react";

export type Density = "comfortable" | "compact";

interface DensityContextValue {
  density: Density;
  setDensity: (d: Density) => void;
  toggle: () => void;
}

const STORAGE_KEY = "cguardiq.density";
const DensityContext = createContext<DensityContextValue | null>(null);

function readInitial(): Density {
  try {
    const v = localStorage.getItem(STORAGE_KEY);
    if (v === "compact" || v === "comfortable") return v;
  } catch {
    /* ignore */
  }
  return "comfortable";
}

function apply(density: Density) {
  document.documentElement.dataset.density = density;
}

export function DensityProvider({ children }: { children: React.ReactNode }) {
  const [density, setDensityState] = useState<Density>(readInitial);

  useEffect(() => {
    apply(density);
    try {
      localStorage.setItem(STORAGE_KEY, density);
    } catch {
      /* ignore */
    }
  }, [density]);

  const value = useMemo<DensityContextValue>(
    () => ({
      density,
      setDensity: setDensityState,
      toggle: () =>
        setDensityState((d) => (d === "comfortable" ? "compact" : "comfortable")),
    }),
    [density],
  );

  return <DensityContext.Provider value={value}>{children}</DensityContext.Provider>;
}

export function useDensity(): DensityContextValue {
  const ctx = useContext(DensityContext);
  if (!ctx) {
    // Tolerate consumption outside the provider (e.g. in tests) by returning
    // a sensible default rather than throwing — the UI still renders.
    return {
      density: "comfortable",
      setDensity: () => undefined,
      toggle: () => undefined,
    };
  }
  return ctx;
}