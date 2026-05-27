import type { Meta, StoryObj } from "@storybook/react";
import React from "react";
import { AdminShell } from "./AdminShell";
import { PageHeader } from "../PageHeader/PageHeader";
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
  TableCaption,
} from "../../components/Table/Table";
import { Badge } from "../../components/Badge/Badge";
import { Avatar } from "../../components/Avatar/Avatar";
import { Button } from "../../components/Button/Button";
import { Input } from "../../components/Input/Input";
import {
  LayoutDashboard,
  Users,
  KeyRound,
  Activity,
  FileText,
  ShieldCheck,
  Search,
  Plus,
  ArrowUpRight,
} from "lucide-react";

const meta: Meta<typeof AdminShell> = {
  title: "Layouts/AdminShell",
  component: AdminShell,
  parameters: {
    layout: "fullscreen",
  },
};

export default meta;
type Story = StoryObj<typeof AdminShell>;

const mockNavigation = [
  {
    title: "Core Services",
    items: [
      {
        label: "Dashboard Overview",
        href: "#",
        icon: <LayoutDashboard className="w-4 h-4" />,
        isActive: true,
      },
      {
        label: "Identity Registry",
        href: "#",
        icon: <Users className="w-4 h-4" />,
        badge: 4,
      },
      {
        label: "Access Policies",
        href: "#",
        icon: <KeyRound className="w-4 h-4" />,
      },
    ],
  },
  {
    title: "Advanced Telemetry",
    items: [
      {
        label: "System Telemetry",
        href: "#",
        icon: <Activity className="w-4 h-4" />,
      },
      {
        label: "Event Audit Logs",
        href: "#",
        icon: <FileText className="w-4 h-4" />,
        badge: 12,
      },
      {
        label: "Security Audit",
        href: "#",
        icon: <ShieldCheck className="w-4 h-4" />,
      },
    ],
  },
];

const mockUser = {
  name: "Dhawal D.",
  email: "dhawal.d@wardseal.com",
};

const mockIdentities = [
  {
    name: "Dhawal D.",
    username: "dhawal.d",
    role: "Super Admin",
    status: "success",
    statusLabel: "Active",
    lastActive: "1 min ago",
    key: "ws_live_99d1fa98a287",
  },
  {
    name: "Alice Wang",
    username: "alice.w",
    role: "SecOps Lead",
    status: "success",
    statusLabel: "Active",
    lastActive: "12 min ago",
    key: "ws_live_38bf817cba10",
  },
  {
    name: "Bob Smith",
    username: "bob.s",
    role: "Compliance Auditor",
    status: "warning",
    statusLabel: "Pending Setup",
    lastActive: "2 hours ago",
    key: "ws_pend_77ac2108b3e8",
  },
  {
    name: "Eve Black",
    username: "eve.b",
    role: "External Dev",
    status: "destructive",
    statusLabel: "Revoked",
    lastActive: "3 days ago",
    key: "ws_revk_881ba827160c",
  },
];

export const FullDashboard: Story = {
  args: {
    navigation: mockNavigation,
    user: mockUser,
    onLogout: () => console.log("Logout triggered"),
    onSearchClick: () => console.log("Search triggered"),
    onNotificationClick: () => console.log("Notifications opened"),
    topHeaderActions: (
      <Button variant="outline" size="sm" className="flex items-center gap-1">
        <span>Upgrade Node</span>
        <ArrowUpRight className="w-3.5 h-3.5 opacity-50" />
      </Button>
    ),
    children: (
      <div className="flex flex-col h-full overflow-hidden">
        <PageHeader
          title="Active Identity Registry"
          description="Manage cryptographic authentication keys, roles, and status."
          breadcrumbs={[
            { label: "Dashboard", href: "#" },
            { label: "Identities", href: "#" },
            { label: "Registry" },
          ]}
          search={
            <Input
              placeholder="Search registry..."
              icon={<Search className="w-4 h-4" />}
              className="h-9 text-xs"
            />
          }
          actions={
            <Button variant="primary" size="sm" className="flex items-center gap-1.5">
              <Plus className="w-3.5 h-3.5" />
              <span>Enroll User</span>
            </Button>
          }
        />
        <div className="flex-1 p-6 overflow-y-auto custom-scrollbar">
          <div className="rounded-xl border border-border bg-card p-6 shadow-card">
            <Table>
              <TableCaption>MFA active credentials status as of 2026</TableCaption>
              <TableHeader>
                <TableRow>
                  <TableHead>Identity</TableHead>
                  <TableHead>System Role</TableHead>
                  <TableHead>Key Status</TableHead>
                  <TableHead>Last Active</TableHead>
                  <TableHead className="text-right">Active Token</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {mockIdentities.map((identity) => (
                  <TableRow key={identity.username}>
                    <TableCell className="font-semibold flex items-center gap-3">
                      <Avatar name={identity.username} size={28} />
                      <div>
                        <div className="text-on-surface font-semibold text-sm">{identity.name}</div>
                        <div className="text-on-surface-variant/40 text-xs">@{identity.username}</div>
                      </div>
                    </TableCell>
                    <TableCell className="text-on-surface-variant/80 font-medium text-xs">
                      {identity.role}
                    </TableCell>
                    <TableCell>
                      <Badge variant={identity.status as any}>{identity.statusLabel}</Badge>
                    </TableCell>
                    <TableCell className="text-on-surface-variant/60 font-semibold text-xs">
                      {identity.lastActive}
                    </TableCell>
                    <TableCell className="text-right font-mono text-[11px] text-on-surface-variant/50">
                      {identity.key}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </div>
      </div>
    ),
  },
};
