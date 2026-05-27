import type { Meta, StoryObj } from "@storybook/react";
import React from "react";
import {
  Table,
  TableHeader,
  TableBody,
  TableFooter,
  TableRow,
  TableHead,
  TableCell,
  TableCaption,
  GlassTable,
  GlassTableHeader,
  GlassTableRow,
  GlassTableHead,
} from "./Table";
import { Badge } from "../Badge/Badge";
import { Avatar } from "../Avatar/Avatar";

const meta: Meta<typeof Table> = {
  title: "Components/Table",
  component: Table,
  tags: ["autodocs"],
};

export default meta;
type Story = StoryObj<typeof Table>;

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

export const Standard: Story = {
  render: () => (
    <CardWrapper title="Standard Table" description="System identity registry listing.">
      <Table>
        <TableCaption>Active cryptographically verified system administrators</TableCaption>
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
    </CardWrapper>
  ),
};

export const Glass: Story = {
  render: () => (
    <CardWrapper title="Glassmorphic Table" description="Secure telemetry log of active connection states." isGlass>
      <GlassTable>
        <TableCaption>Secure active sessions and system telemetry</TableCaption>
        <GlassTableHeader>
          <GlassTableRow>
            <GlassTableHead>Identity</GlassTableHead>
            <GlassTableHead>System Role</GlassTableHead>
            <GlassTableHead>Key Status</GlassTableHead>
            <GlassTableHead>Last Active</GlassTableHead>
            <GlassTableHead className="text-right">Active Token</GlassTableHead>
          </GlassTableRow>
        </GlassTableHeader>
        <TableBody>
          {mockIdentities.map((identity) => (
            <GlassTableRow key={identity.username}>
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
            </GlassTableRow>
          ))}
        </TableBody>
      </GlassTable>
    </CardWrapper>
  ),
};

// Simple helper wrapper card for clean display in Storybook
function CardWrapper({
  children,
  title,
  description,
  isGlass = false,
}: {
  children: React.ReactNode;
  title: string;
  description: string;
  isGlass?: boolean;
}) {
  return (
    <div
      className={
        isGlass
          ? "relative overflow-hidden rounded-xl border border-white/5 bg-black/40 backdrop-blur-xl p-6 shadow-card"
          : "rounded-xl border border-border bg-card p-6 text-card-foreground shadow-card"
      }
    >
      <div className="flex flex-col space-y-1.5 mb-6">
        <h3 className="text-base font-bold leading-none tracking-tight text-on-surface">{title}</h3>
        <p className="text-xs font-semibold text-on-surface-variant/40 uppercase tracking-tight mt-0.5">
          {description}
        </p>
      </div>
      {children}
    </div>
  );
}
