import { render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import UsersPage from "@/app/users/page";
import { AuthProvider } from "@/components/auth/AuthContext";
import { ProtectedRoute } from "@/components/auth/ProtectedRoute";
import { Sidebar } from "@/components/layout/sidebar";
import { TooltipProvider } from "@/components/ui/tooltip";
import { fetchMe } from "@/services/authService";
import { listUsers } from "@/services/usersService";
import type { AuthUser, Role } from "@/types/auth";

const navigation = vi.hoisted(() => ({
  pathname: "/dashboard",
  router: { replace: vi.fn(), push: vi.fn() },
}));

vi.mock("next/navigation", () => ({
  usePathname: () => navigation.pathname,
  useRouter: () => navigation.router,
}));
vi.mock("@/services/authService", () => ({ fetchMe: vi.fn() }));
vi.mock("@/services/usersService", () => ({ listUsers: vi.fn() }));

function signInAs(role: Role) {
  const user: AuthUser = {
    id: "user-1", name: "Test User", email: "user@example.test", role,
    isActive: true, createdAt: null, lastLoginAt: null, organization_id: "org-1",
  };
  localStorage.setItem("authToken", "test-token");
  vi.mocked(fetchMe).mockResolvedValue(user);
}

function renderProtectedPage() {
  return render(
    <AuthProvider>
      <ProtectedRoute><p>Protected content</p></ProtectedRoute>
    </AuthProvider>,
  );
}

describe("authentication and role-based access", () => {
  beforeEach(() => {
    navigation.pathname = "/dashboard";
    vi.mocked(fetchMe).mockReset();
    vi.mocked(listUsers).mockResolvedValue([]);
  });

  it("redirects a guest to login and preserves the requested path", async () => {
    renderProtectedPage();
    await waitFor(() => expect(navigation.router.replace).toHaveBeenCalledWith("/login?next=%2Fdashboard"));
    expect(screen.queryByText("Protected content")).toBeNull();
    expect(fetchMe).not.toHaveBeenCalled();
  });

  it("restores a stored session and shows the requested content", async () => {
    signInAs("user");
    renderProtectedPage();
    expect(await screen.findByText("Protected content")).toBeVisible();
    expect(fetchMe).toHaveBeenCalledOnce();
    expect(navigation.router.replace).not.toHaveBeenCalled();
  });

  it("rejects a tenant admin on the operator route", async () => {
    navigation.pathname = "/operator/organizations";
    signInAs("admin");
    renderProtectedPage();
    await waitFor(() => expect(navigation.router.replace).toHaveBeenCalledWith("/dashboard"));
    expect(screen.queryByText("Protected content")).toBeNull();
  });

  it("redirects the platform operator away from tenant pages", async () => {
    signInAs("operator");
    renderProtectedPage();
    await waitFor(() => expect(navigation.router.replace).toHaveBeenCalledWith("/operator"));
    expect(screen.queryByText("Protected content")).toBeNull();
  });

  it("renders protected content for an operator on a platform route", async () => {
    navigation.pathname = "/operator/organizations";
    signInAs("operator");
    renderProtectedPage();
    expect(await screen.findByText("Protected content")).toBeVisible();
    expect(navigation.router.replace).not.toHaveBeenCalled();
  });

  it("clears an invalid stored session and hides protected content", async () => {
    localStorage.setItem("authToken", "expired-token");
    vi.mocked(fetchMe).mockRejectedValue(new Error("Session expired"));
    renderProtectedPage();
    await waitFor(() => expect(navigation.router.replace).toHaveBeenCalledWith("/login?next=%2Fdashboard"));
    expect(localStorage.getItem("authToken")).toBeNull();
    expect(screen.queryByText("Protected content")).toBeNull();
  });

  it("hides the admin link and user management actions from a viewer", async () => {
    signInAs("viewer");
    render(
      <AuthProvider>
        <TooltipProvider>
          <Sidebar collapsed={false} onToggle={vi.fn()} />
          <UsersPage />
        </TooltipProvider>
      </AuthProvider>,
    );
    expect(await screen.findByRole("link", { name: "Dashboard" })).toBeVisible();
    expect(screen.queryByRole("link", { name: "Users" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Create User" })).toBeNull();
    expect(listUsers).not.toHaveBeenCalled();
  });

  it("shows the user management action and loads the directory for an admin", async () => {
    signInAs("admin");
    render(<AuthProvider><UsersPage /></AuthProvider>);
    expect(await screen.findByRole("button", { name: "Create User" })).toBeEnabled();
    await waitFor(() => expect(listUsers).toHaveBeenCalledOnce());
  });
});
