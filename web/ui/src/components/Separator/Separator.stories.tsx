import type { Meta, StoryObj } from "@storybook/react";
import React from "react";
import { Separator } from "./Separator";

const meta: Meta<typeof Separator> = {
  title: "Components/Separator",
  component: Separator,
  tags: ["autodocs"],
};

export default meta;
type Story = StoryObj<typeof Separator>;

export const Horizontal: Story = {
  render: () => (
    <div className="max-w-xs">
      <div className="space-y-1">
        <h4 className="text-sm font-bold leading-none text-on-surface">WardSeal Gateway Config</h4>
        <p className="text-[10px] text-on-surface-variant/40 uppercase tracking-widest font-semibold">
          Active network rules list.
        </p>
      </div>
      <Separator className="my-4" />
      <div className="flex h-5 items-center space-x-4 text-xs font-semibold text-on-surface-variant/70">
        <div>node-01</div>
        <Separator orientation="vertical" />
        <div>10.0.1.45</div>
        <Separator orientation="vertical" />
        <div>Active</div>
      </div>
    </div>
  ),
};
