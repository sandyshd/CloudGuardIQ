import { useAuth } from "../../hooks/useAuth";
import { Button } from "../ui/button";
import { LogOut, User } from "lucide-react";

export function Topbar() {
  const { user, logout } = useAuth();

  return (
    <header className="flex h-16 items-center justify-between border-b px-6">
      <h1 className="text-lg font-semibold">Cloud Security & FinOps</h1>
      <div className="flex items-center gap-4">
        {user && (
          <div className="flex items-center gap-2 text-sm">
            <User className="h-4 w-4" />
            <span>{user.name}</span>
          </div>
        )}
        <Button variant="ghost" size="icon" onClick={logout}>
          <LogOut className="h-4 w-4" />
        </Button>
      </div>
    </header>
  );
}
