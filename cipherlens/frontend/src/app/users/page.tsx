"use client";

import { useState, useEffect, useCallback } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/components/auth/AuthContext";
import { listUsers, createUser, updateUser, deleteUser } from "@/services/usersService";
import type { AuthUser, Role } from "@/types/auth";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Loader2, Pencil, Trash2, UserPlus } from "lucide-react";

export default function UsersPage() {
  const { isAdmin } = useAuth();
  const router = useRouter();
  const [users, setUsers] = useState<AuthUser[]>([]);
  const [loading, setLoading] = useState(true);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editingUser, setEditingUser] = useState<AuthUser | null>(null);
  const [form, setForm] = useState({
    name: "",
    email: "",
    password: "",
    role: "user" as Role,
  });
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!isAdmin) {
      router.push("/dashboard");
    }
  }, [isAdmin, router]);

  const loadUsers = useCallback(async () => {
    try {
      setUsers(await listUsers());
    } catch {
      // ignore
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (isAdmin) {
      void loadUsers();
    }
  }, [isAdmin, loadUsers]);

  const openCreate = () => {
    setEditingUser(null);
    setForm({ name: "", email: "", password: "", role: "user" });
    setDialogOpen(true);
  };

  const openEdit = (u: AuthUser) => {
    setEditingUser(u);
    setForm({ name: u.name, email: u.email, password: "", role: u.role });
    setDialogOpen(true);
  };

  const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

  const handleSave = async () => {
    if (!form.name.trim()) {
      alert("Ingresá el nombre.");
      return;
    }
    if (!editingUser) {
      const email = form.email.trim();
      if (!EMAIL_RE.test(email)) {
        alert("Ingresá un email válido.");
        return;
      }
      if (!form.password) {
        alert("Ingresá la contraseña.");
        return;
      }
    }
    setSaving(true);
    try {
      if (editingUser) {
        await updateUser(editingUser.id, { name: form.name, role: form.role });
      } else {
        await createUser({
          name: form.name,
          email: form.email,
          password: form.password,
          role: form.role,
        });
      }
      setDialogOpen(false);
      await loadUsers();
    } catch (err) {
      alert(err instanceof Error ? err.message : "Error al guardar usuario");
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (u: AuthUser) => {
    if (!confirm(`¿Eliminar usuario ${u.email}?`)) return;
    try {
      await deleteUser(u.id);
      await loadUsers();
    } catch (err) {
      alert(err instanceof Error ? err.message : "Error al eliminar usuario");
    }
  };

  if (!isAdmin) return null;

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle>Users</CardTitle>
          <Button onClick={openCreate}>
            <UserPlus className="mr-2 h-4 w-4" />
            Create User
          </Button>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="flex justify-center py-8">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Email</TableHead>
                  <TableHead>Role</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {users.map((u) => (
                  <TableRow key={u.id}>
                    <TableCell className="font-medium">{u.name}</TableCell>
                    <TableCell>{u.email}</TableCell>
                    <TableCell>
                      <Badge
                        variant={
                          u.role === "admin"
                            ? "destructive"
                            : u.role === "lead"
                              ? "secondary"
                              : "outline"
                        }
                      >
                        {u.role}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <Badge variant={u.isActive ? "default" : "outline"}>
                        {u.isActive ? "Active" : "Inactive"}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right">
                      <Button size="sm" variant="ghost" onClick={() => openEdit(u)}>
                        <Pencil className="h-4 w-4" />
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => void handleDelete(u)}
                      >
                        <Trash2 className="h-4 w-4 text-destructive" />
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{editingUser ? "Edit User" : "Create User"}</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <Input
              placeholder="Name"
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
            />
            <Input
              placeholder="Email"
              type="email"
              autoComplete={editingUser ? "email" : "off"}
              value={form.email}
              disabled={!!editingUser}
              onChange={(e) => setForm({ ...form, email: e.target.value })}
            />
            {!editingUser && (
              <Input
                placeholder="Password"
                type="password"
                autoComplete="new-password"
                value={form.password}
                onChange={(e) => setForm({ ...form, password: e.target.value })}
              />
            )}
            <Select
              value={form.role}
              onValueChange={(v) => setForm({ ...form, role: v as Role })}
            >
              <SelectTrigger>
                <SelectValue placeholder="Role" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="admin">Admin</SelectItem>
                <SelectItem value="lead">Lead</SelectItem>
                <SelectItem value="user">User</SelectItem>
              </SelectContent>
            </Select>
            <Button
              onClick={() => void handleSave()}
              disabled={saving}
              className="w-full"
            >
              {saving && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Save
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
