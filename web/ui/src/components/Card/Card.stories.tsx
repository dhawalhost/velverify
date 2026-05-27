import type { Meta, StoryObj } from "@storybook/react";
import { Card, CardHeader, CardTitle, CardDescription, CardContent, CardFooter } from "./Card";
import { Button } from "../Button/Button";
import { ShieldCheck, Users, Activity } from "lucide-react";
import React from "react";

const meta: Meta<typeof Card> = {
  title: "Components/Card",
  component: Card,
  tags: ["autodocs"],
  argTypes: {
    isGlass: {
      control: "boolean",
    },
  },
};

export default meta;
type Story = StoryObj<typeof Card>;

export const Standard: Story = {
  render: (args: React.ComponentProps<typeof Card>) => (
    <Card className="w-[380px]" {...args}>
      <CardHeader>
        <div className="flex items-center gap-3">
          <div className="p-2 bg-primary/5 rounded-lg text-primary">
            <Users className="w-5 h-5" />
          </div>
          <div>
            <CardTitle>Identity Groups</CardTitle>
            <CardDescription>Manage user roles</CardDescription>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        <p className="text-sm text-on-surface-variant/70 leading-relaxed font-medium">
          Deploy and organize security parameters across groups of individual user accounts to establish structured access policies.
        </p>
      </CardContent>
      <CardFooter>
        <Button variant="outline" className="w-full">Configure Groups</Button>
      </CardFooter>
    </Card>
  ),
  args: {
    isGlass: false,
  },
};

export const GlassCard: Story = {
  render: (args: React.ComponentProps<typeof Card>) => (
    <Card className="w-[380px]" {...args}>
      <CardHeader>
        <div className="flex items-center gap-3">
          <div className="p-2 bg-white/10 rounded-lg text-primary">
            <Activity className="w-5 h-5 text-primary" />
          </div>
          <div>
            <CardTitle>Security Posture</CardTitle>
            <CardDescription>Real-time analytics</CardDescription>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        <p className="text-sm text-on-surface-variant/70 leading-relaxed font-medium">
          Monitoring end-to-end user activity and security hygiene scores. There are currently no outstanding critical actions.
        </p>
      </CardContent>
      <CardFooter>
        <Button variant="glass" className="w-full">View Activity logs</Button>
      </CardFooter>
    </Card>
  ),
  args: {
    isGlass: true,
  },
};
