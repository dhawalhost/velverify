import * as React from "react";
import { cn } from "../../lib/utils";
import { ShieldCheck, Menu, X, Bell, Search, LogOut, ChevronRight } from "lucide-react";
import { Avatar } from "../../components/Avatar/Avatar";

export interface NavigationItem {
  label: string;
  href?: string;
  icon?: React.ReactNode;
  isActive?: boolean;
  badge?: string | number;
  onClick?: () => void;
}

export interface NavigationGroup {
  title: string;
  items: NavigationItem[];
}

export interface AdminShellProps extends React.HTMLAttributes<HTMLDivElement> {
  navigation: NavigationGroup[];
  user: {
    name: string;
    email: string;
    avatarUrl?: string;
  };
  onLogout?: () => void;
  onSearchClick?: () => void;
  onNotificationClick?: () => void;
  brandName?: string;
  topHeaderActions?: React.ReactNode;
}

const AdminShell = React.forwardRef<HTMLDivElement, AdminShellProps>(
  (
    {
      className,
      navigation,
      user,
      onLogout,
      onSearchClick,
      onNotificationClick,
      brandName = "WardSeal",
      topHeaderActions,
      children,
      ...props
    },
    ref
  ) => {
    const [isMobileOpen, setIsMobileOpen] = React.useState(false);

    return (
      <div
        ref={ref}
        className={cn("flex h-screen w-screen bg-background overflow-hidden relative font-sans text-on-surface", className)}
        {...props}
      >
        {/* ── BACKGROUND GLOW DECORATIONS (Premium Cyberpunk) ── */}
        <div className="absolute top-[-20%] left-[-10%] w-[500px] h-[500px] bg-primary/5 rounded-full blur-[120px] pointer-events-none z-0" />
        <div className="absolute bottom-[-10%] right-[-10%] w-[400px] h-[400px] bg-accent/5 rounded-full blur-[100px] pointer-events-none z-0" />

        {/* ── SIDEBAR (DESKTOP & MOBILE TRANSITION) ── */}
        <aside
          className={cn(
            "fixed inset-y-0 left-0 z-40 w-64 bg-surface-container-low border-r border-border flex flex-col justify-between transform transition-transform duration-300 ease-in-out md:translate-x-0 md:static shrink-0 h-full",
            isMobileOpen ? "translate-x-0" : "-translate-x-full"
          )}
        >
          {/* Brand Header */}
          <div className="h-16 px-6 border-b border-border flex items-center justify-between shrink-0">
            <div className="flex items-center gap-2.5">
              <div className="w-8 h-8 rounded-lg bg-primary/10 border border-primary/30 flex items-center justify-center shadow-lg shadow-primary/5 shrink-0">
                <ShieldCheck className="w-4 h-4 text-primary" />
              </div>
              <span className="font-bold text-sm tracking-wider uppercase text-on-surface">
                {brandName}
              </span>
            </div>
            {/* Mobile close button */}
            <button
              onClick={() => setIsMobileOpen(false)}
              className="md:hidden p-1 text-on-surface-variant/40 hover:text-on-surface hover:bg-surface-container rounded-md"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* Navigation Items (Scrollable) */}
          <div className="flex-1 overflow-y-auto custom-scrollbar px-4 py-6 space-y-6">
            {navigation.map((group) => (
              <div key={group.title} className="space-y-2">
                <h3 className="px-3 text-[10px] font-bold uppercase tracking-widest text-on-surface-variant/30">
                  {group.title}
                </h3>
                <ul className="space-y-0.5">
                  {group.items.map((item) => (
                    <li key={item.label}>
                      {item.href ? (
                        <a
                          href={item.href}
                          onClick={item.onClick}
                          className={cn(
                            "flex items-center justify-between px-3 py-2 rounded-lg text-xs font-semibold tracking-tight transition-all duration-200 group/nav",
                            item.isActive
                              ? "bg-primary/5 text-primary border-l-2 border-primary pl-2.5 font-bold"
                              : "text-on-surface-variant/60 hover:text-on-surface hover:bg-surface-container/50"
                          )}
                        >
                          <div className="flex items-center gap-2.5">
                            {item.icon && (
                              <div
                                className={cn(
                                  "w-4 h-4 transition-colors shrink-0",
                                  item.isActive
                                    ? "text-primary"
                                    : "text-on-surface-variant/40 group-hover/nav:text-on-surface"
                                )}
                              >
                                {item.icon}
                              </div>
                            )}
                            <span>{item.label}</span>
                          </div>
                          {item.badge !== undefined && (
                            <span
                              className={cn(
                                "px-1.5 py-0.5 rounded text-[10px] font-bold tracking-tight",
                                item.isActive
                                  ? "bg-primary/10 text-primary"
                                  : "bg-surface-container-highest text-on-surface-variant/50"
                              )}
                            >
                              {item.badge}
                            </span>
                          )}
                        </a>
                      ) : (
                        <button
                          onClick={item.onClick}
                          className={cn(
                            "w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs font-semibold tracking-tight text-left transition-all duration-200 group/nav",
                            item.isActive
                              ? "bg-primary/5 text-primary border-l-2 border-primary pl-2.5 font-bold"
                              : "text-on-surface-variant/60 hover:text-on-surface hover:bg-surface-container/50"
                          )}
                        >
                          <div className="flex items-center gap-2.5">
                            {item.icon && (
                              <div
                                className={cn(
                                  "w-4 h-4 transition-colors shrink-0",
                                  item.isActive
                                    ? "text-primary"
                                    : "text-on-surface-variant/40 group-hover/nav:text-on-surface"
                                )}
                              >
                                {item.icon}
                              </div>
                            )}
                            <span>{item.label}</span>
                          </div>
                          {item.badge !== undefined && (
                            <span
                              className={cn(
                                "px-1.5 py-0.5 rounded text-[10px] font-bold tracking-tight",
                                item.isActive
                                  ? "bg-primary/10 text-primary"
                                  : "bg-surface-container-highest text-on-surface-variant/50"
                              )}
                            >
                              {item.badge}
                            </span>
                          )}
                        </button>
                      )}
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>

          {/* User Profile Footer */}
          <div className="p-4 border-t border-border bg-surface-container-low/50 shrink-0">
            <div className="flex items-center justify-between gap-2.5">
              <div className="flex items-center gap-2.5 min-w-0">
                <Avatar name={user.name} size={32} />
                <div className="min-w-0">
                  <div className="text-xs font-bold tracking-tight text-on-surface truncate">
                    {user.name}
                  </div>
                  <div className="text-[10px] font-semibold text-on-surface-variant/40 truncate">
                    {user.email}
                  </div>
                </div>
              </div>
              {onLogout && (
                <button
                  onClick={onLogout}
                  className="p-1.5 text-on-surface-variant/40 hover:text-destructive hover:bg-destructive/5 rounded-md transition-colors shrink-0"
                  title="Logout"
                >
                  <LogOut className="w-4 h-4" />
                </button>
              )}
            </div>
          </div>
        </aside>

        {/* ── MOBILE OVERLAY ── */}
        {isMobileOpen && (
          <div
            onClick={() => setIsMobileOpen(false)}
            className="fixed inset-0 bg-black/60 backdrop-blur-sm z-30 md:hidden"
          />
        )}

        {/* ── MAIN CONTENT CONTAINER ── */}
        <div className="flex-1 flex flex-col min-w-0 overflow-hidden h-full z-10">
          {/* Top Navbar */}
          <header className="h-16 px-6 border-b border-border bg-surface-container-low/50 backdrop-blur-sm flex items-center justify-between shrink-0">
            <div className="flex items-center gap-4">
              {/* Mobile menu trigger */}
              <button
                onClick={() => setIsMobileOpen(true)}
                className="md:hidden p-1.5 text-on-surface-variant/60 hover:text-on-surface hover:bg-surface-container rounded-md shrink-0"
              >
                <Menu className="w-5 h-5" />
              </button>

              {/* Quick Search trigger */}
              {onSearchClick && (
                <button
                  onClick={onSearchClick}
                  className="hidden md:flex items-center gap-2 px-3 py-1.5 text-xs text-on-surface-variant/30 hover:text-on-surface-variant/60 bg-surface-container/30 hover:bg-surface-container/60 border border-outline/10 rounded-lg transition-all w-56 text-left"
                >
                  <Search className="w-3.5 h-3.5" />
                  <span className="font-semibold">Search credentials...</span>
                  <kbd className="ml-auto text-[10px] bg-surface-container-highest border border-outline/10 px-1 rounded text-on-surface-variant/50">
                    ⌘K
                  </kbd>
                </button>
              )}
            </div>

            {/* Actions & Notifications */}
            <div className="flex items-center gap-4">
              {topHeaderActions}

              {onNotificationClick && (
                <button
                  onClick={onNotificationClick}
                  className="relative p-1.5 text-on-surface-variant/60 hover:text-on-surface hover:bg-surface-container rounded-md transition-colors shrink-0"
                >
                  <Bell className="w-4.5 h-4.5" />
                  <span className="absolute top-1.5 right-1.5 w-2 h-2 rounded-full bg-primary animate-pulse" />
                </button>
              )}
            </div>
          </header>

          {/* Page Body */}
          <main className="flex-1 overflow-y-auto custom-scrollbar bg-background/25">
            {children}
          </main>
        </div>
      </div>
    );
  }
);
AdminShell.displayName = "AdminShell";

export { AdminShell };
