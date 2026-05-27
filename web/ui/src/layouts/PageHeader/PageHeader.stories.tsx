import type { Meta, StoryObj } from "@storybook/react";
import React from "react";
import { PageHeader } from "./PageHeader";
import { Button } from "../../components/Button/Button";
import { Input } from "../../components/Input/Input";
import { Search, Plus, RefreshCw, Download } from "lucide-react";

const meta: Meta<typeof PageHeader> = {
  title: "Layouts/PageHeader",
  component: PageHeader,
  tags: ["autodocs"],
};

export default meta;
type Story = StoryObj<typeof PageHeader>;

export const Default: Story = {
  args: {
    title: "Identity Registry",
    description: "Manage cryptographically verified system users and MFA status.",
    breadcrumbs: [
      { label: "Dashboard", href: "#" },
      { label: "Identities", href: "#" },
      { label: "Registry" },
    ],
  },
};

export const WithActions: Story = {
  args: {
    title: "Access Policy Manager",
    description: "Configure dynamic authentication criteria and sign-in factors.",
    breadcrumbs: [
      { label: "Dashboard", href: "#" },
      { label: "Policies" },
    ],
    actions: (
      <>
        <Button variant="outline" size="sm" className="flex items-center gap-1.5">
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Sync Status</span>
        </Button>
        <Button variant="primary" size="sm" className="flex items-center gap-1.5">
          <Plus className="w-3.5 h-3.5" />
          <span>Create Policy</span>
        </Button>
      </>
    ),
  },
};

export const Comprehensive: Story = {
  args: {
    title: "Authentication Telemetry Logs",
    description: "Real-time auditing of multi-factor login challenges and device states.",
    breadcrumbs: [
      { label: "Dashboard", href: "#" },
      { label: "Logs", href: "#" },
      { label: "Active Sessions" },
    ],
    search: (
      <Input
        placeholder="Filter log streams..."
        icon={<Search className="w-4 h-4" />}
        className="h-9 text-xs"
      />
    ),
    actions: (
      <Button variant="glass" size="sm" className="flex items-center gap-1.5">
        <Download className="w-3.5 h-3.5" />
        <span>Export CSV</span>
      </Button>
    ),
  },
};
