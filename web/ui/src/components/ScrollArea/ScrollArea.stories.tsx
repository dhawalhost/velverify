import type { Meta, StoryObj } from "@storybook/react";
import React from "react";
import { ScrollArea } from "./ScrollArea";

const meta: Meta<typeof ScrollArea> = {
  title: "Components/ScrollArea",
  component: ScrollArea,
  tags: ["autodocs"],
};

export default meta;
type Story = StoryObj<typeof ScrollArea>;

export const Default: Story = {
  render: () => (
    <ScrollArea className="h-48 w-64 rounded-md border border-border p-4">
      <div className="text-xs font-bold uppercase tracking-wider text-primary mb-4">
        Live Security Stream logs
      </div>
      <div className="space-y-3 font-mono text-[10px] text-on-surface-variant/70">
        {Array.from({ length: 20 }).map((_, i) => (
          <div key={i} className="border-b border-on-surface/5 pb-2">
            [10:45:{(i + 12).toString().padStart(2, "0")}] {"node-01 -> challenge: "}
            <span className="text-on-surface font-semibold">
              ws_challenge_hash_88bbf{i}
            </span>
          </div>
        ))}
      </div>
    </ScrollArea>
  ),
};
