import { useEffect, useState } from "react";
import { getConfig } from "../../api/config";

export function DemoBanner() {
  const [show, setShow] = useState(false);

  useEffect(() => {
    let cancelled = false;
    getConfig().then((cfg) => {
      if (!cancelled) setShow(Boolean(cfg.demo_mode));
    });
    return () => {
      cancelled = true;
    };
  }, []);

  if (!show) return null;

  return (
    <div className="border-b border-amber-300 bg-amber-50 px-4 py-2 text-sm text-amber-900">
      <span className="font-semibold">Demo mode:</span> CloudGuardIQ is showing
      sample findings because authentication is disabled or no Azure
      subscription has been linked. Add a subscription on the{" "}
      <a href="/settings" className="font-medium underline">
        Settings
      </a>{" "}
      page to view your real cloud posture.
    </div>
  );
}
