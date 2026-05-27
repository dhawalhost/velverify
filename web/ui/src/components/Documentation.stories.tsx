import type { Meta, StoryObj } from "@storybook/react";
import React from "react";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "./Card/Card";
import { Button } from "./Button/Button";
import { Badge } from "./Badge/Badge";
import { Input } from "./Input/Input";
import { Label } from "./Label/Label";
import { Checkbox } from "./Checkbox/Checkbox";
import { Switch } from "./Switch/Switch";
import { Separator } from "./Separator/Separator";
import { Skeleton } from "./Skeleton/Skeleton";
import { Progress } from "./Progress/Progress";
import { Avatar } from "./Avatar/Avatar";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "./Tabs/Tabs";
import { ScrollArea } from "./ScrollArea/ScrollArea";
import { PageHeader } from "../layouts/PageHeader/PageHeader";
import { BookOpen, Key, Layout, Eye, Terminal } from "lucide-react";

const meta: Meta = {
  title: "Documentation/Handbook",
  parameters: {
    layout: "fullscreen",
  },
};

export default meta;
type Story = StoryObj;

interface PropDoc {
  name: string;
  type: string;
  required: boolean;
  defaultValue?: string;
  description: string;
}

interface ComponentDoc {
  name: string;
  description: string;
  props: PropDoc[];
  illustration: React.ReactNode;
}

const componentRegistry: ComponentDoc[] = [
  {
    name: "Button",
    description: "Takable tactile trigger button with gradient neon glow, transparent glass, or sleek outline layouts.",
    illustration: (
      <div className="flex flex-wrap items-center gap-3">
        <Button variant="primary" size="sm">Primary</Button>
        <Button variant="outline" size="sm">Outline</Button>
        <Button variant="glass" size="sm">Glass Mode</Button>
        <Button variant="primary" size="sm" isLoading>Syncing</Button>
      </div>
    ),
    props: [
      { name: "variant", type: "'primary' | 'secondary' | 'outline' | 'ghost' | 'glass'", required: false, defaultValue: "'primary'", description: "Sets the visual design skin factor." },
      { name: "size", type: "'sm' | 'md' | 'lg'", required: false, defaultValue: "'md'", description: "Sets height and padding rules." },
      { name: "isLoading", type: "boolean", required: false, defaultValue: "false", description: "Enables spinners and locks click actions." },
      { name: "asChild", type: "boolean", required: false, defaultValue: "false", description: "Enables Radix slot composition." }
    ]
  },
  {
    name: "Input",
    description: "Form input fields equipped with modular icon slotting, dynamic error boundaries, and custom focuses.",
    illustration: (
      <div className="w-64">
        <Input placeholder="Enter username..." icon={<Key className="w-4 h-4" />} />
      </div>
    ),
    props: [
      { name: "icon", type: "React.ReactNode", required: false, description: "Adds a custom search, lock, or mail icon inside the trigger." },
      { name: "error", type: "string", required: false, description: "Displays warning subtext under the boundary and sets neon red outlines." }
    ]
  },
  {
    name: "Avatar",
    description: "BoringAvatar graphics provider tied directly to WardSeal's HSL corporate palette.",
    illustration: (
      <div className="flex gap-2.5">
        <Avatar name="dhawal.d" size={32} variant="marble" />
        <Avatar name="alice.w" size={32} variant="beam" />
        <Avatar name="bob.s" size={32} variant="pixel" />
      </div>
    ),
    props: [
      { name: "name", type: "string", required: true, description: "Seeds the color marble distribution generation." },
      { name: "size", type: "number", required: false, defaultValue: "32", description: "Pixel dimension for height and width grids." },
      { name: "variant", type: "'marble' | 'beam' | 'pixel' | 'sunset' | 'ring' | 'bauhaus'", required: false, defaultValue: "'marble'", description: "Specifies graphic type." }
    ]
  },
  {
    name: "Badge",
    description: "Unified capsules to depict connection posture, MFA states, or account compliance checkmarks.",
    illustration: (
      <div className="flex gap-2">
        <Badge variant="primary">Secured</Badge>
        <Badge variant="success">Active</Badge>
        <Badge variant="warning">Pending</Badge>
        <Badge variant="destructive">Revoked</Badge>
      </div>
    ),
    props: [
      { name: "variant", type: "'primary' | 'secondary' | 'success' | 'warning' | 'destructive' | 'neutral'", required: false, defaultValue: "'primary'", description: "Dictates boundary fill colors." }
    ]
  },
  {
    name: "Checkbox",
    description: "Custom checkbox widget carrying glowing neon outlines, custom checks, and active factors.",
    illustration: (
      <div className="flex items-center gap-2">
        <Checkbox id="doc-check" defaultChecked />
        <Label htmlFor="doc-check">Posture verified</Label>
      </div>
    ),
    props: [
      { name: "checked", type: "boolean | 'indeterminate'", required: false, description: "Specifies checked state." },
      { name: "disabled", type: "boolean", required: false, description: "Bypasses clicks and fades opacity." }
    ]
  },
  {
    name: "Switch",
    description: "Premium cyberpunk toggle switch with sliding animations and HSL indicators.",
    illustration: (
      <div className="flex items-center gap-2">
        <Switch id="doc-switch" defaultChecked />
        <Label htmlFor="doc-switch">Enforce MFA factor</Label>
      </div>
    ),
    props: [
      { name: "checked", type: "boolean", required: false, description: "Governs toggle slide." },
      { name: "disabled", type: "boolean", required: false, description: "Fades and prevents user toggle triggers." }
    ]
  },
  {
    name: "Progress",
    description: "Glowing linear bar loader displaying download progress or secure handshake syncs.",
    illustration: (
      <div className="w-56">
        <Progress value={65} />
      </div>
    ),
    props: [
      { name: "value", type: "number", required: false, defaultValue: "0", description: "Loading completion percentage (0 - 100)." }
    ]
  },
  {
    name: "Skeleton",
    description: "Neon pulsing loader placeholders to mock loading structures and dashboard grids.",
    illustration: (
      <div className="w-56 space-y-2">
        <Skeleton className="h-4 w-full" />
        <Skeleton className="h-3 w-3/4" />
      </div>
    ),
    props: [
      { name: "className", type: "string", required: false, description: "Assign custom height, width or border radius rules." }
    ]
  }
];

function HandbookRenderer() {
  const [activeComponent, setActiveComponent] = React.useState<string>("Button");
  const selectedDoc = componentRegistry.find((c) => c.name === activeComponent) || componentRegistry[0];

  return (
    <div className="min-h-screen bg-[#0A0A0C] text-on-surface font-sans flex flex-col">
      {/* ── HEADER ── */}
      <PageHeader
        title="Brand UI Component Handbook"
        description="Illustrated catalog documenting universal components, layouts, and prop typings."
        breadcrumbs={[
          { label: "Design System", href: "#" },
          { label: "Handbook" }
        ]}
      />

      <div className="flex-1 flex max-w-7xl w-full mx-auto p-6 md:p-8 gap-8 overflow-hidden">
        {/* ── NAVIGATION SIDEBAR ── */}
        <aside className="w-64 bg-surface-container-low border border-border rounded-xl p-4 shrink-0 flex flex-col space-y-4 max-h-[70vh] overflow-y-auto custom-scrollbar">
          <div className="flex items-center gap-2 px-2 text-xs font-bold uppercase tracking-wider text-on-surface-variant/40">
            <BookOpen className="w-3.5 h-3.5" />
            <span>Components list</span>
          </div>
          <nav className="flex flex-col space-y-1">
            {componentRegistry.map((c) => (
              <button
                key={c.name}
                onClick={() => setActiveComponent(c.name)}
                className={`flex items-center justify-between px-3 py-2 rounded-lg text-xs font-semibold tracking-tight transition-all duration-200 ${
                  activeComponent === c.name
                    ? "bg-primary/5 text-primary font-bold border-l-2 border-primary pl-2.5"
                    : "text-on-surface-variant/60 hover:text-on-surface hover:bg-surface-container/50"
                }`}
              >
                <span>{c.name}</span>
                {activeComponent === c.name && <Eye className="w-3.5 h-3.5 text-primary" />}
              </button>
            ))}
          </nav>
        </aside>

        {/* ── HANDBOOK DETAIL SHEET ── */}
        <main className="flex-1 space-y-6 overflow-y-auto custom-scrollbar pr-2 max-h-[85vh]">
          {/* Header Card */}
          <Card isGlass>
            <CardHeader>
              <CardTitle className="text-xl font-bold">{selectedDoc.name}</CardTitle>
              <CardDescription>{selectedDoc.description}</CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              {/* Illustration Block */}
              <div className="rounded-xl border border-white/5 bg-black/40 p-6 flex flex-col space-y-3">
                <div className="text-[10px] font-bold uppercase tracking-widest text-on-surface-variant/30 flex items-center gap-1.5">
                  <Terminal className="w-3.5 h-3.5 text-primary" />
                  <span>Interactive illustration preview</span>
                </div>
                <div className="py-4 px-2">
                  {selectedDoc.illustration}
                </div>
              </div>

              {/* Props Specification Table */}
              <div className="space-y-3">
                <div className="text-[10px] font-bold uppercase tracking-widest text-on-surface-variant/30 flex items-center gap-1.5">
                  <Layout className="w-3.5 h-3.5 text-primary" />
                  <span>Props specifications handbook</span>
                </div>
                
                <div className="overflow-x-auto border border-border rounded-xl">
                  <table className="w-full text-xs text-left border-collapse">
                    <thead>
                      <tr className="bg-surface-container border-b border-border">
                        <th className="p-3 font-bold text-on-surface-variant/50 uppercase text-[10px] tracking-wider">Prop Name</th>
                        <th className="p-3 font-bold text-on-surface-variant/50 uppercase text-[10px] tracking-wider">Type</th>
                        <th className="p-3 font-bold text-on-surface-variant/50 uppercase text-[10px] tracking-wider text-center">Required</th>
                        <th className="p-3 font-bold text-on-surface-variant/50 uppercase text-[10px] tracking-wider">Default</th>
                        <th className="p-3 font-bold text-on-surface-variant/50 uppercase text-[10px] tracking-wider">Usage & Details</th>
                      </tr>
                    </thead>
                    <tbody>
                      {selectedDoc.props.length > 0 ? (
                        selectedDoc.props.map((p) => (
                          <tr key={p.name} className="border-b border-border/50 hover:bg-white/5 transition-colors">
                            <td className="p-3 font-mono font-bold text-primary">{p.name}</td>
                            <td className="p-3 font-mono text-on-surface-variant/80 text-[11px]">{p.type}</td>
                            <td className="p-3 text-center">
                              {p.required ? (
                                <Badge variant="destructive">Yes</Badge>
                              ) : (
                                <Badge variant="neutral">No</Badge>
                              )}
                            </td>
                            <td className="p-3 font-mono text-on-surface-variant/60">{p.defaultValue || "-"}</td>
                            <td className="p-3 text-on-surface-variant/80 font-medium leading-relaxed">{p.description}</td>
                          </tr>
                        ))
                      ) : (
                        <tr>
                          <td colSpan={5} className="p-4 text-center font-semibold text-on-surface-variant/40 uppercase tracking-widest italic">
                            Inherits standard HTML element attributes.
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </CardContent>
          </Card>
        </main>
      </div>
    </div>
  );
}

export const HandbookCatalog: Story = {
  render: () => <HandbookRenderer />,
};
