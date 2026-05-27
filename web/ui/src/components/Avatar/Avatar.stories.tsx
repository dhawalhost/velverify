import type { Meta, StoryObj } from "@storybook/react";
import { Avatar } from "./Avatar";
import React from "react";

const meta: Meta<typeof Avatar> = {
  title: "Components/Avatar",
  component: Avatar,
  tags: ["autodocs"],
  argTypes: {
    name: {
      control: "text",
    },
    size: {
      control: "number",
    },
    variant: {
      control: "select",
      options: ["marble", "beam", "pixel", "sunset", "ring", "bauhaus"],
    },
  },
};

export default meta;
type Story = StoryObj<typeof Avatar>;

export const DefaultMarble: Story = {
  args: {
    name: "admin@wardseal.com",
    size: 40,
    variant: "marble",
  },
};

export const Beam: Story = {
  args: {
    name: "user_identity_beta",
    size: 40,
    variant: "beam",
  },
};

export const LargeRing: Story = {
  args: {
    name: "sec-admin-root",
    size: 64,
    variant: "ring",
  },
};

export const SmallAvatar: Story = {
  args: {
    name: "member_id",
    size: 24,
    variant: "marble",
  },
};
