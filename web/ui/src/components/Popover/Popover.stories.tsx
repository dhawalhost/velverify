import type { Meta, StoryObj } from "@storybook/react";
import React from "react";
import { Popover, PopoverTrigger, PopoverContent } from "./Popover";
import { Button } from "../Button/Button";
import { Settings, RefreshCw } from "lucide-react";

const meta: Meta = {
  title: "Components/Popover",
  component: Popover,
  tags: ["autodocs"],
};

export default meta;
type Story = StoryObj;

export const Default: Story = {
  render: () => (
    <div className="p-12 flex justify-center items-center">
      <Popover>
        <PopoverTrigger asChild>
          <Button variant="outline" size="sm" className="flex items-center gap-1.5">
            <Settings className="w-4 h-4 opacity-50" />
            <span>Connection Profile</span>
          </Button>
        </PopoverTrigger>
        <PopoverContent className="w-80">
          <div className="grid gap-4">
            <div className="space-y-2">
              <h4 className="font-bold leading-none text-sm text-on-surface">Secure Telemetry Config</h4>
              <p className="text-[10px] text-on-surface-variant/40 uppercase tracking-widest font-semibold mt-0.5">
                Active connection configurations.
              </p>
            </div>
            <div className="grid gap-2 text-xs font-semibold text-on-surface-variant/70 leading-relaxed">
              <div className="flex justify-between border-b border-on-surface/5 pb-2">
                <span>Active Server</span>
                <span className="font-mono text-[10px] text-primary">us-east-01.wardseal.net</span>
              </div>
              <div className="flex justify-between border-b border-on-surface/5 pb-2">
                <span>Handshake Ping</span>
                <span className="font-mono text-[10px] text-primary">12 ms</span>
              </div>
              <div className="flex justify-between pb-1">
                <span>Fallback Gateway</span>
                <span className="font-mono text-[10px] text-on-surface-variant/40">Not Configured</span>
              </div>
            </div>
            <Button variant="primary" size="sm" className="w-full flex items-center justify-center gap-1.5 mt-2">
              <RefreshCw className="w-3.5 h-3.5" />
              <span>Reconnect Gateway</span>
            </Button>
          </div>
        </PopoverContent>
      </Popover>
    </div>
  ),
};
