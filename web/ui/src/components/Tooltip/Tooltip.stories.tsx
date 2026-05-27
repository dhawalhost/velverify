import type { Meta, StoryObj } from "@storybook/react";
import React from "react";
import { Tooltip, TooltipTrigger, TooltipContent, TooltipProvider } from "./Tooltip";
import { Button } from "../Button/Button";
import { HelpCircle } from "lucide-react";

const meta: Meta = {
  title: "Components/Tooltip",
  component: Tooltip,
  tags: ["autodocs"],
};

export default meta;
type Story = StoryObj;

export const Default: Story = {
  render: () => (
    <TooltipProvider>
      <div className="p-12 flex justify-center items-center">
        <Tooltip>
          <TooltipTrigger asChild>
            <Button variant="outline" size="sm" className="flex items-center gap-1.5">
              <HelpCircle className="w-4 h-4 opacity-50" />
              <span>TPM Factor</span>
            </Button>
          </TooltipTrigger>
          <TooltipContent>
            Trusted Platform Module verification status
          </TooltipContent>
        </Tooltip>
      </div>
    </TooltipProvider>
  ),
};
