import type { Meta, StoryObj } from "@storybook/react";
import React from "react";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "./Tabs";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "../Card/Card";

const meta: Meta<typeof Tabs> = {
  title: "Components/Tabs",
  component: Tabs,
  tags: ["autodocs"],
};

export default meta;
type Story = StoryObj<typeof Tabs>;

export const Default: Story = {
  render: () => (
    <Tabs defaultValue="credentials" className="w-[400px]">
      <TabsList className="grid w-full grid-cols-2">
        <TabsTrigger value="credentials">Credentials</TabsTrigger>
        <TabsTrigger value="policy">Access Policy</TabsTrigger>
      </TabsList>
      <TabsContent value="credentials">
        <Card>
          <CardHeader>
            <CardTitle>System Credentials</CardTitle>
            <CardDescription>Active keys loaded into session.</CardDescription>
          </CardHeader>
          <CardContent className="text-xs text-on-surface-variant/70 leading-relaxed font-semibold">
            Primary verified credential: YubiKey 5C NFC. Posture state matches corporate criteria.
          </CardContent>
        </Card>
      </TabsContent>
      <TabsContent value="policy">
        <Card>
          <CardHeader>
            <CardTitle>Access Posture Policy</CardTitle>
            <CardDescription>Active rules and criteria verification</CardDescription>
          </CardHeader>
          <CardContent className="text-xs text-on-surface-variant/70 leading-relaxed font-semibold">
            Strict MFA and posture checking is enabled. Legacy credentials without PIN signature are currently rejected.
          </CardContent>
        </Card>
      </TabsContent>
    </Tabs>
  ),
};
