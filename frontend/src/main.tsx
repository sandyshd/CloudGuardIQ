import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { PublicClientApplication, EventType } from "@azure/msal-browser";
import { MsalProvider } from "@azure/msal-react";
import { msalConfig } from "./auth/msalConfig";
import App from "./App";
import { ThemeProvider } from "./components/layout/ThemeProvider";
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

export const msalInstance = new PublicClientApplication(msalConfig);

async function startApp() {
  await msalInstance.initialize();

  try {
    const response = await msalInstance.handleRedirectPromise();
    if (response?.account) {
      msalInstance.setActiveAccount(response.account);
    }
  } catch (error) {
    console.error("Redirect error:", error);
  }

  const accounts = msalInstance.getAllAccounts();
  if (accounts.length > 0 && !msalInstance.getActiveAccount()) {
    msalInstance.setActiveAccount(accounts[0]);
  }

  msalInstance.addEventCallback((event) => {
    if (event.eventType === EventType.LOGIN_SUCCESS && event.payload) {
      const payload = event.payload as {
        account: Parameters<typeof msalInstance.setActiveAccount>[0];
      };
      msalInstance.setActiveAccount(payload.account);
    }
  });

  const root = document.getElementById("root");
  if (root) {
    createRoot(root).render(
      <StrictMode>
        <MsalProvider instance={msalInstance}>
          <ThemeProvider>
            <ToastProvider>
              <App />
            </ToastProvider>
          </ThemeProvider>
        </MsalProvider>
      </StrictMode>
    );
  }
}

startApp();
