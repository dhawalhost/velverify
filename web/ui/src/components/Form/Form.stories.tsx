import type { Meta, StoryObj } from "@storybook/react";
import React from "react";
import { FormField, FormGroup, FormSection } from "./Form";
import { Card, CardHeader, CardTitle, CardDescription, CardContent, CardFooter } from "../Card/Card";
import { Label } from "../Label/Label";
import { Input } from "../Input/Input";
import { Switch } from "../Switch/Switch";
import { Button } from "../Button/Button";

const meta: Meta = {
  title: "Components/Form",
  component: FormGroup,
  tags: ["autodocs"],
};

export default meta;
type Story = StoryObj;

export const EnrollmentForm: Story = {
  render: () => (
    <div className="max-w-md">
      <Card isGlass>
        <CardHeader>
          <CardTitle>Enroll Secure Hardware</CardTitle>
          <CardDescription>Configure external credential parameters</CardDescription>
        </CardHeader>
        <CardContent>
          <FormGroup>
            <FormSection title="Core Attributes" description="Hardware identifiers">
              <div className="grid gap-4">
                <FormField>
                  <Label htmlFor="enroll-name">Credential Custom Name</Label>
                  <Input id="enroll-name" placeholder="E.g., YubiKey 5C NFC Primary" />
                </FormField>
                <FormField>
                  <Label htmlFor="enroll-id">Hardware Vendor Serial</Label>
                  <Input id="enroll-id" placeholder="ws_vendor_sn_..." />
                </FormField>
              </div>
            </FormSection>
            
            <FormSection title="Access Factor Constraints" description="Gateway authentication controls">
              <div className="flex items-center justify-between p-3 rounded-lg bg-white/5 border border-white/5">
                <div className="space-y-0.5">
                  <Label htmlFor="strict-factor" className="text-on-surface text-xs font-semibold normal-case">Strict POSTURE signature check</Label>
                  <p className="text-[10px] text-on-surface-variant/40 font-medium">Verify TPM signature challenges</p>
                </div>
                <Switch id="strict-factor" defaultChecked />
              </div>
            </FormSection>
          </FormGroup>
        </CardContent>
        <CardFooter className="justify-end gap-2">
          <Button variant="outline" size="sm">Cancel</Button>
          <Button variant="primary" size="sm">Sync Credential</Button>
        </CardFooter>
      </Card>
    </div>
  ),
};
