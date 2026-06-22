import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { MsalProvider } from "@azure/msal-react";
import {
  getActiveMsalInstance,
  initializeMsal,
} from "./auth/instances";
import App from "./App";
import { ThemeProvider } from "./components/layout/ThemeProvider";
import { DensityProvider } from "./components/layout/DensityProvider";
import { ToastProvider } from "./components/ui/toast";
import "./index.css";

export const PENDING_CONSENT_CALLBACK_KEY = "cguardiq.pendingConsentCallback";
(function capturePendingConsentCallback(): void {
  try {
    const url = new URL(window.location.href);
    if (url.searchParams.get("consent") !== "callback") return;
    const payload = {
      tenant: url.searchParams.get("tenant") ?? "",
      admin_consent: url.searchParams.get("admin_consent") ?? "",
      error: url.searchParams.get("error") ?? "",
      error_description: url.searchParams.get("error_description") ?? "",
      state: url.searchParams.get("state") ?? "",
      capturedAt: new Date().toISOString(),
    };
    sessionStorage.setItem(PENDING_CONSENT_CALLBACK_KEY, JSON.stringify(payload));
  } catch {
    /* sessionStorage unavailable or URL parse failure -- nothing to do. */
  }
})();

// The active MSAL instance reflects the persisted provider choice
// (workforce or CIAM) and is stable for the lifetime of a page load.
export const msalInstance = getActiveMsalInstance();

async function startApp() {
  await initializeMsal();

  const root = document.getElementById("root");
  if (root) {
    createRoot(root).render(
      <StrictMode>
        <MsalProvider instance={msalInstance}>
          <ThemeProvider>
            <DensityProvider>
              <ToastProvider>
              <App />
            </ToastProvider>
            </DensityProvider>
          </ThemeProvider>
        </MsalProvider>
      </StrictMode>
    );
  }
}

startApp();
