import { BrowserRouter, Routes, Route } from "react-router-dom";
import { Layout } from "./components/layout/Layout";
import { RequireAuth } from "./auth/RequireAuth";
import { SubscriptionProvider } from "./auth/SubscriptionContext";
import { Dashboard } from "./pages/Dashboard";
import { Findings } from "./pages/Findings";
import { AIFix } from "./pages/AIFix";
import { FinOps } from "./pages/FinOps";
import { Compliance } from "./pages/Compliance";
import { SelfHeal } from "./pages/SelfHeal";
import { Settings } from "./pages/Settings";

export default function App() {
  return (
    <BrowserRouter>
      <RequireAuth>
        <SubscriptionProvider>
          <Routes>
            <Route element={<Layout />}>
              <Route path="/" element={<Dashboard />} />
              <Route path="/findings" element={<Findings />} />
              <Route path="/findings/:id" element={<AIFix />} />
              <Route path="/ai-fix" element={<AIFix />} />
              <Route path="/finops" element={<FinOps />} />
              <Route path="/compliance" element={<Compliance />} />
              <Route path="/self-heal" element={<SelfHeal />} />
              <Route path="/settings" element={<Settings />} />
            </Route>
          </Routes>
        </SubscriptionProvider>
      </RequireAuth>
    </BrowserRouter>
  );
}
