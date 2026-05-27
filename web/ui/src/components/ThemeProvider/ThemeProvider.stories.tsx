import type { Meta, StoryObj } from "@storybook/react";
import React from "react";
import { ThemeProvider, useTheme } from "./ThemeProvider";
import { Button } from "../Button/Button";
import { Badge } from "../Badge/Badge";
import { Card, CardContent, CardHeader, CardTitle, CardDescription, CardFooter } from "../Card/Card";
import { Input } from "../Input/Input";
import { Switch } from "../Switch/Switch";
import { Avatar } from "../Avatar/Avatar";
import { Progress } from "../Progress/Progress";
import { Separator } from "../Separator/Separator";
import { Logo } from "../Logo/Logo";
import { Sun, Moon, Shield, Bell, Settings, CheckCircle, AlertTriangle, XCircle, ChevronRight, Lock } from "lucide-react";

const meta: Meta<typeof ThemeProvider> = {
  title: "Theme/ThemeProvider",
  component: ThemeProvider,
  tags: ["autodocs"],
  parameters: {
    layout: "fullscreen",
  },
};

export default meta;
type Story = StoryObj<typeof ThemeProvider>;

// ── Helpers ──────────────────────────────────────

function ThemeToggle() {
  const { theme, toggleTheme } = useTheme();
  return (
    <button
      onClick={toggleTheme}
      className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-border bg-card text-on-surface text-xs font-semibold transition-all hover:bg-accent"
    >
      {theme === "dark" ? (
        <><Sun className="w-3.5 h-3.5 text-primary" /> Light Mode</>
      ) : (
        <><Moon className="w-3.5 h-3.5 text-primary" /> Dark Mode</>
      )}
    </button>
  );
}

// ── Full Showcase ─────────────────────────────────

function FullThemeShowcase() {
  const { theme } = useTheme();

  return (
    <div className="min-h-screen bg-background text-foreground transition-colors duration-300">
      {/* Header */}
      <header className="sticky top-0 z-50 border-b border-border bg-card/80 backdrop-blur-md">
        <div className="flex items-center justify-between px-6 py-3">
          <Logo variant="full" logoColor="brand" textColor={theme === "dark" ? "white" : "mono"} className="h-7 w-auto" />
          <div className="flex items-center gap-3">
            <Badge variant="success" className="text-[10px]">Live Preview</Badge>
            <ThemeToggle />
          </div>
        </div>
      </header>

      <div className="max-w-5xl mx-auto px-6 py-10 space-y-12">

        {/* Current Theme Banner */}
        <div className="flex items-center gap-4 p-4 rounded-xl border border-primary/30 bg-primary/5">
          {theme === "dark"
            ? <Moon className="w-5 h-5 text-primary flex-shrink-0" />
            : <Sun className="w-5 h-5 text-primary flex-shrink-0" />}
          <div>
            <p className="text-sm font-bold text-on-surface">
              {theme === "dark" ? "Dark Mode" : "Light Mode"} Active
            </p>
            <p className="text-xs text-muted-foreground mt-0.5">
              All components adapt to the current theme via CSS variable overrides on the <code className="text-primary bg-primary/10 px-1 py-0.5 rounded text-[10px]">.{theme}</code> document class.
            </p>
          </div>
        </div>

        {/* ── Buttons ── */}
        <section className="space-y-4">
          <h2 className="text-xs font-bold text-on-surface-variant uppercase tracking-widest">Buttons</h2>
          <div className="flex flex-wrap gap-3">
            <Button variant="primary">Primary Action</Button>
            <Button variant="secondary">Secondary</Button>
            <Button variant="outline">Outline</Button>
            <Button variant="ghost">Ghost</Button>
            <Button variant="glass">Glass</Button>
            <Button variant="primary" isLoading>Loading...</Button>
            <Button variant="primary" disabled>Disabled</Button>
          </div>
          <div className="flex flex-wrap gap-3">
            <Button variant="primary" size="sm">Small</Button>
            <Button variant="primary" size="md">Medium</Button>
            <Button variant="primary" size="lg">Large</Button>
          </div>
        </section>

        <Separator />

        {/* ── Badges ── */}
        <section className="space-y-4">
          <h2 className="text-xs font-bold text-on-surface-variant uppercase tracking-widest">Badges</h2>
          <div className="flex flex-wrap gap-2">
            <Badge variant="default">Default</Badge>
            <Badge variant="primary">Primary</Badge>
            <Badge variant="secondary">Secondary</Badge>
            <Badge variant="success">Active</Badge>
            <Badge variant="warning">Warning</Badge>
            <Badge variant="error">Critical</Badge>
            <Badge variant="neutral">Neutral</Badge>
            <Badge variant="outline">Outline</Badge>
            <Badge variant="destructive">Destructive</Badge>
          </div>
        </section>

        <Separator />

        {/* ── Cards ── */}
        <section className="space-y-4">
          <h2 className="text-xs font-bold text-on-surface-variant uppercase tracking-widest">Cards</h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <Card>
              <CardHeader>
                <CardTitle>Standard Card</CardTitle>
                <CardDescription>Surface container elevation</CardDescription>
              </CardHeader>
              <CardContent>
                <p className="text-xs text-muted-foreground leading-relaxed">
                  Cards adapt surface backgrounds, border colors, and shadow depths based on active theme.
                </p>
              </CardContent>
              <CardFooter className="justify-between">
                <span className="text-xs text-muted-foreground">Updated now</span>
                <Button variant="ghost" size="sm">View <ChevronRight className="w-3 h-3 ml-1" /></Button>
              </CardFooter>
            </Card>

            <Card isGlass>
              <CardHeader>
                <CardTitle>Glass Card</CardTitle>
                <CardDescription>Frosted blur overlay</CardDescription>
              </CardHeader>
              <CardContent>
                <p className="text-xs text-muted-foreground leading-relaxed">
                  Glass cards shift from dark-opaque to frosted-white glass in light mode automatically.
                </p>
              </CardContent>
              <CardFooter>
                <Badge variant="primary" className="text-[10px]">Glass Morphism</Badge>
              </CardFooter>
            </Card>

            <Card>
              <CardHeader>
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-lg bg-primary/10">
                    <Shield className="w-4 h-4 text-primary" />
                  </div>
                  <div>
                    <CardTitle>Security Status</CardTitle>
                    <CardDescription>MFA Enforced</CardDescription>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-3">
                <Progress value={87} className="h-1.5" />
                <p className="text-xs text-muted-foreground">87% of users compliant</p>
              </CardContent>
            </Card>
          </div>
        </section>

        <Separator />

        {/* ── Inputs ── */}
        <section className="space-y-4">
          <h2 className="text-xs font-bold text-on-surface-variant uppercase tracking-widest">Inputs & Controls</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-3">
              <Input placeholder="Search users, groups, policies…" />
              <Input placeholder="Email address" type="email" />
              <Input placeholder="Disabled input" disabled />
            </div>
            <div className="space-y-4">
              <div className="flex items-center justify-between p-3 rounded-lg border border-border bg-card">
                <div>
                  <p className="text-sm font-semibold text-on-surface">MFA Enforcement</p>
                  <p className="text-xs text-muted-foreground mt-0.5">Require 2FA for all admin users</p>
                </div>
                <Switch defaultChecked />
              </div>
              <div className="flex items-center justify-between p-3 rounded-lg border border-border bg-card">
                <div>
                  <p className="text-sm font-semibold text-on-surface">Audit Logging</p>
                  <p className="text-xs text-muted-foreground mt-0.5">Record all access events</p>
                </div>
                <Switch />
              </div>
            </div>
          </div>
        </section>

        <Separator />

        {/* ── Avatars & Users ── */}
        <section className="space-y-4">
          <h2 className="text-xs font-bold text-on-surface-variant uppercase tracking-widest">Avatars</h2>
          <div className="flex items-center gap-4 flex-wrap">
            <Avatar name="Dhawal Dyavanpalli" size={24} />
            <Avatar name="Arjun Sharma" size={32} />
            <Avatar name="Priya Patel" size={40} />
            <Avatar name="Kunal Mehta" size={48} />
            <Avatar name="Maya Chen" size={56} variant="beam" />
          </div>
        </section>

        <Separator />

        {/* ── State Colors ── */}
        <section className="space-y-4">
          <h2 className="text-xs font-bold text-on-surface-variant uppercase tracking-widest">Semantic States</h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <div className="flex items-center gap-3 p-3 rounded-lg border border-success/30 bg-success-subtle">
              <CheckCircle className="w-4 h-4 text-success flex-shrink-0" />
              <div>
                <p className="text-xs font-bold text-success">Connection Active</p>
                <p className="text-[10px] text-muted-foreground">All services operational</p>
              </div>
            </div>
            <div className="flex items-center gap-3 p-3 rounded-lg border border-warning/30 bg-warning-subtle">
              <AlertTriangle className="w-4 h-4 text-warning flex-shrink-0" />
              <div>
                <p className="text-xs font-bold text-warning">Certificate Expiring</p>
                <p className="text-[10px] text-muted-foreground">Renew within 14 days</p>
              </div>
            </div>
            <div className="flex items-center gap-3 p-3 rounded-lg border border-error/30 bg-error-subtle">
              <XCircle className="w-4 h-4 text-error flex-shrink-0" />
              <div>
                <p className="text-xs font-bold text-error">Policy Violation</p>
                <p className="text-[10px] text-muted-foreground">3 critical alerts</p>
              </div>
            </div>
          </div>
        </section>

        <Separator />

        {/* ── Progress & Metrics ── */}
        <section className="space-y-4">
          <h2 className="text-xs font-bold text-on-surface-variant uppercase tracking-widest">Progress & Metrics</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="space-y-4">
              <div className="space-y-1.5">
                <div className="flex justify-between text-xs">
                  <span className="text-on-surface font-semibold">SSO Coverage</span>
                  <span className="text-primary font-bold">94%</span>
                </div>
                <Progress value={94} />
              </div>
              <div className="space-y-1.5">
                <div className="flex justify-between text-xs">
                  <span className="text-on-surface font-semibold">MFA Compliance</span>
                  <span className="text-warning font-bold">67%</span>
                </div>
                <Progress value={67} />
              </div>
              <div className="space-y-1.5">
                <div className="flex justify-between text-xs">
                  <span className="text-on-surface font-semibold">Policy Sync Rate</span>
                  <span className="text-error font-bold">31%</span>
                </div>
                <Progress value={31} />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3">
              {[
                { label: "Active Users", value: "4,821", icon: <CheckCircle className="w-4 h-4 text-success" /> },
                { label: "SSO Apps", value: "127", icon: <Lock className="w-4 h-4 text-primary" /> },
                { label: "Alerts Today", value: "18", icon: <Bell className="w-4 h-4 text-warning" /> },
                { label: "Open Tickets", value: "6", icon: <Settings className="w-4 h-4 text-muted-foreground" /> },
              ].map(({ label, value, icon }) => (
                <Card key={label}>
                  <CardContent className="p-4 flex flex-col gap-2">
                    {icon}
                    <p className="text-xl font-bold text-on-surface">{value}</p>
                    <p className="text-[10px] text-muted-foreground font-semibold uppercase tracking-wide">{label}</p>
                  </CardContent>
                </Card>
              ))}
            </div>
          </div>
        </section>

      </div>
    </div>
  );
}

// ── Stories ──────────────────────────────────────

export const DarkMode: Story = {
  render: () => (
    <ThemeProvider forcedTheme="dark">
      <FullThemeShowcase />
    </ThemeProvider>
  ),
};

export const LightMode: Story = {
  render: () => (
    <ThemeProvider forcedTheme="light">
      <FullThemeShowcase />
    </ThemeProvider>
  ),
};

export const InteractiveToggle: Story = {
  render: () => (
    <ThemeProvider defaultTheme="dark" storageKey="storybook-interactive-theme">
      <FullThemeShowcase />
    </ThemeProvider>
  ),
};
