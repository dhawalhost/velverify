import type { Meta, StoryObj } from "@storybook/react";
import React from "react";
import { CommandMenu, type CommandItem } from "./CommandMenu";
import { Button } from "../Button/Button";
import {
  ShieldAlert,
  Settings,
  Users,
  Activity,
  FileText,
  KeyRound,
  RefreshCw,
} from "lucide-react";

const meta: Meta = {
  title: "Components/CommandMenu",
  component: CommandMenu,
  tags: ["autodocs"],
};

export default meta;
type Story = StoryObj;

const mockCommands: CommandItem[] = [
  {
    id: "sync",
    label: "Sync Security Posture",
    category: "System Actions",
    icon: <RefreshCw className="w-4 h-4" />,
    shortcut: "⌘S",
    onClick: () => alert("Syncing posture!"),
  },
  {
    id: "threats",
    label: "View Active Threats",
    category: "Telemetry",
    icon: <ShieldAlert className="w-4 h-4" />,
    onClick: () => alert("Loading threats!"),
  },
  {
    id: "posture",
    label: "Check Posture Status",
    category: "Telemetry",
    icon: <Activity className="w-4 h-4" />,
  },
  {
    id: "identities",
    label: "Manage User Registry",
    category: "Management",
    icon: <Users className="w-4 h-4" />,
    shortcut: "G + U",
  },
  {
    id: "keys",
    label: "Manage MFA Keys",
    category: "Management",
    icon: <KeyRound className="w-4 h-4" />,
  },
  {
    id: "settings",
    label: "System Settings",
    category: "Management",
    icon: <Settings className="w-4 h-4" />,
  },
  {
    id: "logs",
    label: "Export Audit Logs",
    category: "Reports",
    icon: <FileText className="w-4 h-4" />,
    shortcut: "⌘E",
  },
];

export const Default: Story = {
  render: () => {
    const [open, setOpen] = React.useState(false);

    return (
      <div className="p-12 flex flex-col justify-center items-center gap-4">
        <Button onClick={() => setOpen(true)}>Open Command Console</Button>
        <p className="text-xs text-on-surface-variant/40 font-bold uppercase tracking-widest">
          Press <kbd className="bg-surface-container-high border border-outline/10 px-1 rounded font-mono">⌘K</kbd> globally to toggle
        </p>
        <CommandMenu open={open} onOpenChange={setOpen} items={mockCommands} />
      </div>
    );
  },
};
