import type { Meta, StoryObj } from "@storybook/react";
import React from "react";
import {
  Sheet,
  SheetTrigger,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription,
  SheetFooter,
  SheetClose,
} from "./Sheet";
import { Button } from "../Button/Button";
import { Activity, Clock } from "lucide-react";

const meta: Meta<typeof Sheet> = {
  title: "Components/Sheet",
  component: Sheet,
  tags: ["autodocs"],
};

export default meta;
type Story = StoryObj<typeof Sheet>;

export const TelemetryLogs: Story = {
  render: () => (
    <Sheet>
      <SheetTrigger asChild>
        <Button variant="outline">View Device Telemetry</Button>
      </SheetTrigger>
      <SheetContent side="right">
        <SheetHeader>
          <SheetTitle className="flex items-center gap-2">
            <Activity className="w-5 h-5 text-primary" />
            <span>System Telemetry</span>
          </SheetTitle>
          <SheetDescription>
            Real-time audit log stream for the current node.
          </SheetDescription>
        </SheetHeader>
        <div className="space-y-4 py-6">
          <div className="flex items-start gap-3 text-xs leading-normal">
            <Clock className="w-4 h-4 text-on-surface-variant/40 shrink-0 mt-0.5" />
            <div>
              <div className="font-semibold text-on-surface">Verification Challenge Dispatched</div>
              <div className="text-[10px] text-on-surface-variant/40">10:45:12 AM • node-01</div>
            </div>
          </div>
          <div className="flex items-start gap-3 text-xs leading-normal border-t border-on-surface/5 pt-4">
            <Clock className="w-4 h-4 text-primary shrink-0 mt-0.5" />
            <div>
              <div className="font-semibold text-primary">Cryptographic Signature Validated</div>
              <div className="text-[10px] text-on-surface-variant/40">10:45:13 AM • node-01</div>
            </div>
          </div>
        </div>
        <SheetFooter>
          <SheetClose asChild>
            <Button variant="outline" className="w-full">Close Log</Button>
          </SheetClose>
        </SheetFooter>
      </SheetContent>
    </Sheet>
  ),
};
