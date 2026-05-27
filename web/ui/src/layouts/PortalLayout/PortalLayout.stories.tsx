import type { Meta, StoryObj } from "@storybook/react";
import React from "react";
import { PortalLayout } from "./PortalLayout";
import { Card, CardHeader, CardTitle, CardDescription, CardContent, CardFooter } from "../../components/Card/Card";
import { Button } from "../../components/Button/Button";
import { Badge } from "../../components/Badge/Badge";
import { Input } from "../../components/Input/Input";
import { KeyRound, ShieldAlert, Laptop, Eye, HelpCircle } from "lucide-react";

const meta: Meta<typeof PortalLayout> = {
  title: "Layouts/PortalLayout",
  component: PortalLayout,
  parameters: {
    layout: "fullscreen",
  },
};

export default meta;
type Story = StoryObj<typeof PortalLayout>;

const mockLinks = [
  { label: "Overview", href: "#", isActive: true },
  { label: "Credentials", href: "#" },
  { label: "Authorized Devices", href: "#" },
  { label: "Audits & Activity", href: "#" },
];

const mockUser = {
  name: "Dhawal D.",
  email: "dhawal.d@wardseal.com",
};

export const HealthyPortal: Story = {
  args: {
    links: mockLinks,
    user: mockUser,
    nodeStatus: "healthy",
    nodeName: "wardseal-mfa-us-east.node",
    onLogout: () => console.log("Logout clicked"),
    onProfileSettings: () => console.log("Profile clicked"),
    children: (
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Main Status Panel */}
        <div className="lg:col-span-2 space-y-6">
          <Card isGlass>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle>Hardware Security Key Verification</CardTitle>
                  <CardDescription>Configure and enroll YubiKey or Passkeys for MFA signing.</CardDescription>
                </div>
                <Badge variant="success">Secured</Badge>
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-start gap-4 p-4 rounded-lg bg-white/5 border border-white/5">
                <KeyRound className="w-8 h-8 text-primary shrink-0 mt-0.5" />
                <div className="space-y-1">
                  <h4 className="text-sm font-bold text-on-surface">Registered YubiKey 5C NFC</h4>
                  <p className="text-xs text-on-surface-variant/60 font-medium">
                    Added on April 12, 2026. Used for cryptographic proof challenges on primary workspace.
                  </p>
                </div>
              </div>
              <div className="flex items-start gap-4 p-4 rounded-lg bg-white/5 border border-white/5">
                <Laptop className="w-8 h-8 text-primary shrink-0 mt-0.5" />
                <div className="space-y-1">
                  <h4 className="text-sm font-bold text-on-surface">MacBook Pro TouchID Passkey</h4>
                  <p className="text-xs text-on-surface-variant/60 font-medium">
                    Added on May 24, 2026. Local authentication token synced with secure hardware enclave.
                  </p>
                </div>
              </div>
            </CardContent>
            <CardFooter className="justify-between">
              <span className="text-[10px] text-on-surface-variant/40 font-bold uppercase tracking-wider">
                Last modified 3 days ago
              </span>
              <Button variant="primary" size="sm">
                Register New Key
              </Button>
            </CardFooter>
          </Card>
        </div>

        {/* Sidebar Info Panels */}
        <div className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>System Policy Check</CardTitle>
              <CardDescription>Active credential and posture assessment</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center justify-between border-b border-on-surface/5 pb-3">
                <span className="text-xs font-semibold text-on-surface-variant/80">Hardware MFA factor</span>
                <Badge variant="success">Verified</Badge>
              </div>
              <div className="flex items-center justify-between border-b border-on-surface/5 pb-3">
                <span className="text-xs font-semibold text-on-surface-variant/80">Device OS Patch State</span>
                <Badge variant="success">Up to Date</Badge>
              </div>
              <div className="flex items-center justify-between pb-1">
                <span className="text-xs font-semibold text-on-surface-variant/80">Active Access Token</span>
                <Badge variant="success">Valid (2h remaining)</Badge>
              </div>
            </CardContent>
            <CardFooter>
              <Button variant="outline" size="sm" className="w-full">
                View Policy Rulebook
              </Button>
            </CardFooter>
          </Card>
        </div>
      </div>
    ),
  },
};

export const AlertPortal: Story = {
  args: {
    links: mockLinks,
    user: mockUser,
    nodeStatus: "degraded",
    nodeName: "wardseal-mfa-us-west.node",
    onLogout: () => console.log("Logout clicked"),
    onProfileSettings: () => console.log("Profile clicked"),
    children: (
      <div className="max-w-3xl mx-auto space-y-6">
        <Card className="border-destructive/30">
          <CardHeader>
            <div className="flex items-center justify-between">
              <div>
                <CardTitle className="text-destructive flex items-center gap-2">
                  <ShieldAlert className="w-5 h-5 text-destructive" />
                  <span>MFA Token Expired or Revoked</span>
                </CardTitle>
                <CardDescription>Your current login session lacks valid hardware posture certificates.</CardDescription>
              </div>
              <Badge variant="destructive">Critical State</Badge>
            </div>
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-xs text-on-surface-variant/80 font-medium leading-relaxed">
              Your connection origin has changed or your system's hardware token has failed to sync.
              You must re-verify your secure connection using a registered identity card or MFA token.
            </p>
          </CardContent>
          <CardFooter className="gap-3">
            <Button variant="primary" size="sm">
              Verify Identity
            </Button>
            <Button variant="outline" size="sm">
              Ignore & Log Out
            </Button>
          </CardFooter>
        </Card>
      </div>
    ),
  },
};
