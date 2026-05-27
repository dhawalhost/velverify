import type { Meta, StoryObj } from "@storybook/react";
import { Button } from "./Button";
import { ShieldCheck, ArrowRight } from "lucide-react";
import React from "react";

const meta: Meta<typeof Button> = {
  title: "Components/Button",
  component: Button,
  tags: ["autodocs"],
  argTypes: {
    variant: {
      control: "select",
      options: ["primary", "secondary", "outline", "ghost", "glass"],
    },
    size: {
      control: "select",
      options: ["sm", "md", "lg"],
    },
    isLoading: {
      control: "boolean",
    },
    disabled: {
      control: "boolean",
    },
  },
};

export default meta;
type Story = StoryObj<typeof Button>;

export const Primary: Story = {
  args: {
    variant: "primary",
    children: "Secure System",
  },
};

export const Secondary: Story = {
  args: {
    variant: "secondary",
    children: "Back to Safety",
  },
};

export const Outline: Story = {
  args: {
    variant: "outline",
    children: "Cancel Action",
  },
};

export const Ghost: Story = {
  args: {
    variant: "ghost",
    children: "View Logs",
  },
};

export const Glass: Story = {
  args: {
    variant: "glass",
    children: "Tactile Glass Control",
  },
};

export const WithIcon: Story = {
  args: {
    variant: "primary",
    children: (
      <span className="flex items-center gap-2">
        <ShieldCheck className="w-4 h-4" />
        <span>Deploy Policy</span>
        <ArrowRight className="w-4 h-4" />
      </span>
    ),
  },
};

export const Loading: Story = {
  args: {
    variant: "primary",
    isLoading: true,
    children: "Encrypting Keys...",
  },
};
