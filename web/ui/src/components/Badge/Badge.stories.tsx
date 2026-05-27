import type { Meta, StoryObj } from "@storybook/react";
import { Badge } from "./Badge";
import React from "react";

const meta: Meta<typeof Badge> = {
  title: "Components/Badge",
  component: Badge,
  tags: ["autodocs"],
  argTypes: {
    variant: {
      control: "select",
      options: ["primary", "secondary", "success", "warning", "destructive", "neutral"],
    },
  },
};

export default meta;
type Story = StoryObj<typeof Badge>;

export const Active: Story = {
  args: {
    variant: "success",
    children: "Active",
  },
};

export const Pending: Story = {
  args: {
    variant: "warning",
    children: "Pending Approval",
  },
};

export const Suspended: Story = {
  args: {
    variant: "destructive",
    children: "Suspended",
  },
};

export const SystemAdmin: Story = {
  args: {
    variant: "primary",
    children: "System Admin",
  },
};

export const StandardUser: Story = {
  args: {
    variant: "neutral",
    children: "Standard Account",
  },
};
