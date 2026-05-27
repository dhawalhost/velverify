import type { Meta, StoryObj } from "@storybook/react";
import React from "react";
import { Checkbox } from "./Checkbox";
import { Label } from "../Label/Label";

const meta: Meta<typeof Checkbox> = {
  title: "Components/Checkbox",
  component: Checkbox,
  tags: ["autodocs"],
};

export default meta;
type Story = StoryObj<typeof Checkbox>;

export const Default: Story = {
  render: () => (
    <div className="flex items-center gap-2">
      <Checkbox id="terms" />
      <Label htmlFor="terms">Accept terms & conditions</Label>
    </div>
  ),
};

export const SecuredFactor: Story = {
  render: () => (
    <div className="flex items-start gap-2.5 max-w-sm p-4 rounded-lg bg-surface-container border border-border">
      <Checkbox id="secured" defaultChecked />
      <div className="grid gap-1.5 leading-none">
        <Label htmlFor="secured" className="text-on-surface font-semibold text-xs">
          Hardware Security Posture Check
        </Label>
        <p className="text-[10px] text-on-surface-variant/40 leading-normal font-medium">
          Require hardware MFA tokens and TPM validation key challenges for this account.
        </p>
      </div>
    </div>
  ),
};

export const Disabled: Story = {
  render: () => (
    <div className="flex items-center gap-2">
      <Checkbox id="disabled-terms" disabled />
      <Label htmlFor="disabled-terms" className="opacity-70">
        Enforce CCPA restrictions (system default)
      </Label>
    </div>
  ),
};
