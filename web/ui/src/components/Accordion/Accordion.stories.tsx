import type { Meta, StoryObj } from "@storybook/react";
import React from "react";
import { Accordion, AccordionItem, AccordionTrigger, AccordionContent } from "./Accordion";

const meta: Meta = {
  title: "Components/Accordion",
  component: Accordion,
  tags: ["autodocs"],
};

export default meta;
type Story = StoryObj;

export const Default: Story = {
  render: () => (
    <div className="max-w-md p-6 border border-border rounded-xl bg-card">
      <Accordion type="single" collapsible className="w-full">
        <AccordionItem value="item-1">
          <AccordionTrigger>What is physical MFA?</AccordionTrigger>
          <AccordionContent>
            Physical Multi-Factor Authentication relies on dedicated physical hardware (such as YubiKeys or built-in TouchID secure enclaves) to sign cryptographic challenges that verify identity without relying on SMS or passwords.
          </AccordionContent>
        </AccordionItem>
        <AccordionItem value="item-2">
          <AccordionTrigger>Is the posture checker automatic?</AccordionTrigger>
          <AccordionContent>
            Yes. The security posture check automatically audits the device's OS patch level, disk encryption state, and firewall logs upon each authentication handshake.
          </AccordionContent>
        </AccordionItem>
      </Accordion>
    </div>
  ),
};
