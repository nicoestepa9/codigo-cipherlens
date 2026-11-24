"use client";

import { FormEvent, useState } from "react";
import { KeyRound, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useAuth } from "./AuthContext";
import { changeMyPassword } from "@/services/authService";

export function ForcePasswordChange() {
  const { user, logout } = useAuth();
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const open = !!user?.mustChangePassword;

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setError("");
    if (newPassword.length < 8) {
      setError("The new password must be at least 8 characters long.");
      return;
    }
    if (newPassword !== confirmPassword) {
      setError("The new passwords do not match.");
      return;
    }
    setBusy(true);
    try {
      await changeMyPassword(currentPassword, newPassword);
      await logout();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not change the password.");
      setBusy(false);
    }
  }

  return (
    <Dialog open={open}>
      <DialogContent
        showCloseButton={false}
        onEscapeKeyDown={(event) => event.preventDefault()}
        onInteractOutside={(event) => event.preventDefault()}
      >
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <KeyRound className="h-4 w-4 text-primary" />
            Change your temporary password
          </DialogTitle>
          <DialogDescription>
            Your account was created with a temporary password. Set a new one before continuing.
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={handleSubmit} className="space-y-3">
          <div className="space-y-1.5">
            <Label htmlFor="current-password">Current password</Label>
            <Input
              id="current-password"
              type="password"
              autoComplete="current-password"
              value={currentPassword}
              onChange={(event) => setCurrentPassword(event.target.value)}
              required
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="new-password">New password</Label>
            <Input
              id="new-password"
              type="password"
              autoComplete="new-password"
              value={newPassword}
              onChange={(event) => setNewPassword(event.target.value)}
              required
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="confirm-password">Confirm new password</Label>
            <Input
              id="confirm-password"
              type="password"
              autoComplete="new-password"
              value={confirmPassword}
              onChange={(event) => setConfirmPassword(event.target.value)}
              required
            />
          </div>
          {error && <p className="text-sm text-destructive">{error}</p>}
          <div className="flex justify-end gap-2 pt-2">
            <Button type="button" variant="outline" onClick={() => void logout()} disabled={busy}>
              Sign out
            </Button>
            <Button type="submit" disabled={busy}>
              {busy && <Loader2 className="mr-2 h-3.5 w-3.5 animate-spin" />}
              Update password
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}
