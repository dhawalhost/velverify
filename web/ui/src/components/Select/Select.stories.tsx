import type { Meta, StoryObj } from "@storybook/react";
import React from "react";
import {
  Select,
  SelectGroup,
  SelectValue,
  SelectTrigger,
  SelectContent,
  SelectItem,
  SelectLabel,
  SelectSeparator,
} from "./Select";

const meta: Meta<typeof Select> = {
  title: "Components/Select",
  component: Select,
  tags: ["autodocs"],
};

export default meta;
type Story = StoryObj<typeof Select>;

export const Default: Story = {
  render: () => (
    <div className="w-[200px]">
      <Select defaultValue="member">
        <SelectTrigger>
          <SelectValue placeholder="Select role" />
        </SelectTrigger>
        <SelectContent>
          <SelectGroup>
            <SelectLabel>System Roles</SelectLabel>
            <SelectItem value="admin">Administrator</SelectItem>
            <SelectItem value="member">Workspace Member</SelectItem>
            <SelectItem value="auditor">Compliance Auditor</SelectItem>
            <SelectSeparator />
            <SelectItem value="suspended" disabled>Suspended Account</SelectItem>
          </SelectGroup>
        </SelectContent>
      </Select>
    </div>
  ),
};
