import * as React from "react";
import { cn } from "../../lib/utils";
import { ShieldCheck, ChevronDown, CheckCircle2, ShieldAlert, LogOut, User, Settings } from "lucide-react";
import { Avatar } from "../../components/Avatar/Avatar";
import {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
} from "../../components/Dropdown/Dropdown";

export interface PortalLink {
  label: string;
  href?: string;
  isActive?: boolean;
  onClick?: () => void;
}

export interface PortalLayoutProps extends React.HTMLAttributes<HTMLDivElement> {
  links: PortalLink[];
  user: {
    name: string;
    email: string;
    avatarUrl?: string;
  };
  onLogout?: () => void;
  onProfileSettings?: () => void;
  nodeStatus?: "healthy" | "degraded" | "disconnected";
  nodeName?: string;
  brandName?: string;
}

const PortalLayout = React.forwardRef<HTMLDivElement, PortalLayoutProps>(
  (
    {
      className,
      links,
      user,
      onLogout,
      onProfileSettings,
      nodeStatus = "healthy",
      nodeName = "wardseal-node-01.us-east",
      brandName = "WardSeal Portal",
      children,
      ...props
    },
    ref
  ) => {
    return (
      <div
        ref={ref}
        className={cn(
          "min-h-screen w-screen bg-[#0A0A0C] flex flex-col justify-between font-sans text-on-surface relative overflow-x-hidden",
          className
        )}
        {...props}
      >
        {/* ── BACKGROUND ACCENTS ── */}
        <div className="absolute top-[-300px] left-[50%] -translate-x-1/2 w-[800px] h-[500px] bg-primary/5 rounded-full blur-[150px] pointer-events-none z-0" />
        <div className="absolute bottom-[-200px] right-[-100px] w-[500px] h-[400px] bg-accent/5 rounded-full blur-[120px] pointer-events-none z-0" />

        {/* ── TOPBAR HEADER ── */}
        <header className="sticky top-0 z-40 border-b border-white/5 bg-black/40 backdrop-blur-xl shrink-0">
          <div className="max-w-7xl mx-auto h-16 px-4 md:px-8 flex items-center justify-between">
            {/* Logo */}
            <div className="flex items-center gap-6">
              <div className="flex items-center gap-2.5">
                <div className="w-8 h-8 rounded-lg bg-primary/10 border border-primary/30 flex items-center justify-center shadow-lg shadow-primary/5">
                  <ShieldCheck className="w-4 h-4 text-primary" />
                </div>
                <span className="font-bold text-sm tracking-wider uppercase text-on-surface">
                  {brandName}
                </span>
              </div>

              {/* Navigation Links */}
              <nav className="hidden md:flex items-center space-x-1">
                {links.map((link) => (
                  <button
                    key={link.label}
                    onClick={link.onClick}
                    className={cn(
                      "px-3 py-1.5 rounded-lg text-xs font-semibold tracking-tight transition-all duration-200",
                      link.isActive
                        ? "bg-white/5 text-primary font-bold shadow-sm"
                        : "text-on-surface-variant/60 hover:text-on-surface hover:bg-white/5"
                    )}
                  >
                    {link.label}
                  </button>
                ))}
              </nav>
            </div>

            {/* Right side controls */}
            <div className="flex items-center gap-4">
              {/* Telemetry Status Indicator */}
              <div className="hidden lg:flex items-center gap-2.5 px-3 py-1.5 rounded-lg bg-white/5 border border-white/5 font-semibold text-[10px] tracking-tight uppercase">
                <span className="relative flex h-2 w-2">
                  <span
                    className={cn(
                      "animate-ping absolute inline-flex h-full w-full rounded-full opacity-75",
                      nodeStatus === "healthy"
                        ? "bg-primary"
                        : nodeStatus === "degraded"
                        ? "bg-warning"
                        : "bg-destructive"
                    )}
                  />
                  <span
                    className={cn(
                      "relative inline-flex rounded-full h-2 w-2",
                      nodeStatus === "healthy"
                        ? "bg-primary"
                        : nodeStatus === "degraded"
                        ? "bg-warning"
                        : "bg-destructive"
                    )}
                  />
                </span>
                <span className="text-on-surface-variant/60 font-mono truncate max-w-[150px]">
                  {nodeName}
                </span>
              </div>

              {/* User Dropdown Profile */}
              <DropdownMenu>
                <DropdownMenuTrigger className="flex items-center gap-2 p-1 rounded-lg hover:bg-white/5 outline-none transition-colors">
                  <Avatar name={user.name} size={28} />
                  <ChevronDown className="w-4 h-4 text-on-surface-variant/40 hover:text-on-surface" />
                </DropdownMenuTrigger>
                <DropdownMenuContent className="w-56" align="end">
                  <DropdownMenuLabel>
                    <div className="flex flex-col">
                      <span className="text-xs font-bold text-on-surface">{user.name}</span>
                      <span className="text-[10px] font-semibold text-on-surface-variant/40 mt-0.5">
                        {user.email}
                      </span>
                    </div>
                  </DropdownMenuLabel>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem onClick={onProfileSettings}>
                    <User className="mr-2 h-4 w-4 opacity-40" />
                    <span>My Profile</span>
                  </DropdownMenuItem>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem onClick={onLogout} className="text-destructive focus:bg-destructive/10 focus:text-destructive">
                    <LogOut className="mr-2 h-4 w-4" />
                    <span>Sign Out</span>
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            </div>
          </div>
        </header>

        {/* ── MOBILE SYSTEM NAV ── */}
        <nav className="md:hidden border-b border-white/5 bg-black/20 flex items-center justify-around py-2 shrink-0 z-10">
          {links.map((link) => (
            <button
              key={link.label}
              onClick={link.onClick}
              className={cn(
                "px-2.5 py-1 rounded-md text-[10px] font-bold uppercase tracking-wider transition-all",
                link.isActive
                  ? "bg-white/5 text-primary"
                  : "text-on-surface-variant/40 hover:text-on-surface"
              )}
            >
              {link.label}
            </button>
          ))}
        </nav>

        {/* ── CONTENT BODY ── */}
        <main className="flex-1 max-w-7xl w-full mx-auto px-4 md:px-8 py-8 z-10 overflow-y-auto">
          {children}
        </main>

        {/* ── SECURE FOOTER (Premium Layout standard) ── */}
        <footer className="border-t border-white/5 bg-black/40 backdrop-blur-xl py-8 shrink-0 z-10">
          <div className="max-w-7xl mx-auto px-4 md:px-8 flex flex-col md:flex-row items-center justify-between gap-6">
            {/* Brand details */}
            <div className="flex items-center gap-3">
              <ShieldCheck className="w-5 h-5 text-primary opacity-60" />
              <div className="text-[10px] font-semibold text-on-surface-variant/30 uppercase tracking-widest">
                © {new Date().getFullYear()} WARDSEAL SECURITY SYSTEMS Inc. All rights reserved.
              </div>
            </div>

            {/* Compliance Certificates */}
            <div className="flex items-center gap-4 flex-wrap justify-center">
              <ComplianceBadge label="SOC 2 TYPE II" icon={<CheckCircle2 className="w-3 h-3 text-primary" />} />
              <ComplianceBadge label="ISO 27001" icon={<CheckCircle2 className="w-3 h-3 text-primary" />} />
              <ComplianceBadge label="CCPA COMPLIANT" icon={<CheckCircle2 className="w-3 h-3 text-primary" />} />
            </div>
          </div>
        </footer>
      </div>
    );
  }
);
PortalLayout.displayName = "PortalLayout";

// Small localized helper component for compliance items
function ComplianceBadge({ label, icon }: { label: string; icon: React.ReactNode }) {
  return (
    <div className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-white/5 border border-white/5 text-[9px] font-bold tracking-wider text-on-surface-variant/60 uppercase">
      {icon}
      <span>{label}</span>
    </div>
  );
}

export { PortalLayout };
