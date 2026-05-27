import type { Meta, StoryObj } from "@storybook/react";
import React from "react";
import { Label } from "./Label";
import { Input } from "../Input/Input";

const meta: Meta<typeof Label> = {
  title: "Components/Label",
  component: Label,
  tags: ["autodocs"],
};

export default meta;
type Story = StoryObj<typeof Label>;

export const Default: Story = {
  args: {
    children: "Access Token Lifetime",
  },
};

export const WithInput: Story = {
  render: () => (
    <div className="flex flex-col gap-2 max-w-sm">
      <Label htmlFor="api-key">Security Access Token</Label>
      <Input id="api-key" placeholder="ws_live_..." type="text" />
    </div>
  ),
};
