import type { Meta, StoryObj } from "@storybook/react";
import * as React from "react";
import { Logo } from "./Logo";

const meta: Meta<typeof Logo> = {
  title: "Brand/Logo",
  component: Logo,
  parameters: {
    layout: "centered",
  },
  tags: ["autodocs"],
};

export default meta;
type Story = StoryObj<typeof Logo>;

export const DefaultFull: Story = {
  args: {
    variant: "full",
    logoColor: "brand",
    textColor: "white",
    className: "h-12 w-auto",
  },
};

export const ShieldIcon: Story = {
  args: {
    variant: "icon",
    logoColor: "brand",
    className: "h-16 w-auto",
  },
};

export const MonochromaticLogo: Story = {
  render: () => (
    <div className="flex flex-col gap-6 p-6 bg-surface-container rounded-xl border border-border">
      <div>
        <p className="text-xs text-muted-foreground mb-2 font-semibold uppercase">
          Monochromatic Cyan Theme (using Tailwind text classes)
        </p>
        <Logo
          variant="full"
          logoColor="mono"
          textColor="mono"
          className="h-10 w-auto text-cyan-400"
        />
      </div>
      <div>
        <p className="text-xs text-muted-foreground mb-2 font-semibold uppercase">
          Monochromatic Rose Theme
        </p>
        <Logo
          variant="full"
          logoColor="mono"
          textColor="mono"
          className="h-10 w-auto text-rose-400"
        />
      </div>
      <div>
        <p className="text-xs text-muted-foreground mb-2 font-semibold uppercase">
          Dim Muted Logo (using text-muted-foreground)
        </p>
        <Logo
          variant="full"
          logoColor="mono"
          textColor="mono"
          className="h-10 w-auto text-muted-foreground/30"
        />
      </div>
    </div>
  ),
};

export const ResponsiveScales: Story = {
  render: () => (
    <div className="flex flex-col gap-8 p-4">
      <div className="space-y-2">
        <span className="text-[10px] font-bold text-muted-foreground uppercase tracking-widest">
          Micro (Navbar header / sidebar collapsed)
        </span>
        <div className="flex gap-4 items-center">
          <Logo variant="icon" className="h-6 w-auto" />
          <Logo variant="full" className="h-6 w-auto" />
        </div>
      </div>

      <div className="space-y-2">
        <span className="text-[10px] font-bold text-muted-foreground uppercase tracking-widest">
          Standard (Sidebar Header / Dashboard Panel)
        </span>
        <div className="flex gap-6 items-center">
          <Logo variant="icon" className="h-10 w-auto" />
          <Logo variant="full" className="h-10 w-auto" />
        </div>
      </div>

      <div className="space-y-2">
        <span className="text-[10px] font-bold text-muted-foreground uppercase tracking-widest">
          Large (Sign-in / Console Splash Page)
        </span>
        <div className="flex flex-col gap-4">
          <Logo variant="icon" className="h-24 w-auto self-start" />
          <Logo variant="full" className="h-20 w-auto self-start" />
        </div>
      </div>
    </div>
  ),
};
