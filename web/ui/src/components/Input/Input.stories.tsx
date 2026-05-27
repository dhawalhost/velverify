import type { Meta, StoryObj } from "@storybook/react";
import { Input } from "./Input";
import { Search, Lock, Mail } from "lucide-react";
import React from "react";

const meta: Meta<typeof Input> = {
  title: "Components/Input",
  component: Input,
  tags: ["autodocs"],
  argTypes: {
    type: {
      control: "select",
      options: ["text", "password", "email"],
    },
    placeholder: {
      control: "text",
    },
    disabled: {
      control: "boolean",
    },
  },
};

export default meta;
type Story = StoryObj<typeof Input>;

export const Default: Story = {
  args: {
    placeholder: "Enter value...",
  },
};

export const SearchStyle: Story = {
  args: {
    placeholder: "Search identities...",
    icon: <Search className="w-4 h-4" />,
  },
};

export const Password: Story = {
  args: {
    type: "password",
    placeholder: "••••••••",
    icon: <Lock className="w-4 h-4" />,
  },
};

export const Email: Story = {
  args: {
    type: "email",
    placeholder: "admin@wardseal.com",
    icon: <Mail className="w-4 h-4" />,
  },
};

export const WithError: Story = {
  args: {
    placeholder: "username",
    error: "This username is already taken by a workspace administrator.",
  },
};
