import type { Meta, StoryObj } from "@storybook/react";
import React from "react";
import { Switch } from "./Switch";
import { Label } from "../Label/Label";

const meta: Meta<typeof Switch> = {
  title: "Components/Switch",
  component: Switch,
  tags: ["autodocs"],
};

export default meta;
type Story = StoryObj<typeof Switch>;

export const Default: Story = {
  render: () => (
    <div className="flex items-center gap-2">
      <Switch id="toggle-factor" />
      <Label htmlFor="toggle-factor">Enable multi-factor push notifications</Label>
    </div>
  ),
};

export const SecureMode: Story = {
  render: () => (
    <div className="flex items-start gap-3 max-w-sm p-4 rounded-lg bg-surface-container border border-border">
      <Switch id="secure-mode" defaultChecked />
      <div className="grid gap-1.5 leading-none">
        <Label htmlFor="secure-mode" className="text-on-surface font-semibold text-xs">
          Strict Cryptographic Enforcement
        </Label>
        <p className="text-[10px] text-on-surface-variant/40 leading-normal font-medium">
          Require strict signature checking and block legacy public access keys on all gateways.
        </p>
      </div>
    </div>
  ),
};

export const Disabled: Story = {
  render: () => (
    <div className="flex items-center gap-2 opacity-50">
      <Switch id="disabled-toggle" disabled />
      <Label htmlFor="disabled-toggle">Automatic threat blocking</Label>
    </div>
  ),
};
