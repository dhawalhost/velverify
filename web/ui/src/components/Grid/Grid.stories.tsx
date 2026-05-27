import type { Meta, StoryObj } from "@storybook/react";
import * as React from "react";
import { Grid, GridItem } from "./Grid";

const meta: Meta<typeof Grid> = {
  title: "Layout/Grid",
  component: Grid,
  parameters: {
    layout: "fullscreen",
  },
  tags: ["autodocs"],
};

export default meta;
type Story = StoryObj<typeof Grid>;

// Helper preview box for visualization
const DemoBox = ({ children, className = "" }: { children: React.ReactNode; className?: string }) => (
  <div
    className={`flex items-center justify-center p-6 text-xs font-bold rounded-lg border border-primary/20 bg-primary/5 text-primary tracking-tight transition-all duration-300 hover:bg-primary/10 hover:border-primary/40 ${className}`}
  >
    {children}
  </div>
);

export const BasicColumns: Story = {
  render: () => (
    <div className="p-8 space-y-8">
      <div>
        <h3 className="text-sm font-bold text-on-surface uppercase tracking-wider mb-2">
          Equal 4-Column Grid
        </h3>
        <p className="text-xs text-on-surface-variant/60 mb-4">
          A static 4-column layout that is uniform across all screen widths.
        </p>
        <Grid cols={4} gap={4}>
          <DemoBox>Column 1</DemoBox>
          <DemoBox>Column 2</DemoBox>
          <DemoBox>Column 3</DemoBox>
          <DemoBox>Column 4</DemoBox>
        </Grid>
      </div>

      <div>
        <h3 className="text-sm font-bold text-on-surface uppercase tracking-wider mb-2">
          Responsive Layout Wrapper (1 to 2 to 4 cols)
        </h3>
        <p className="text-xs text-on-surface-variant/60 mb-4">
          Wraps to 1 column on mobile, 2 columns on tablet, and 4 columns on desktop/xl screens.
        </p>
        <Grid cols={{ base: 1, sm: 2, md: 2, lg: 4 }} gap="card">
          <DemoBox>Item A (Responsive)</DemoBox>
          <DemoBox>Item B (Responsive)</DemoBox>
          <DemoBox>Item C (Responsive)</DemoBox>
          <DemoBox>Item D (Responsive)</DemoBox>
        </Grid>
      </div>
    </div>
  ),
};

export const SpansAndOffsets: Story = {
  render: () => (
    <div className="p-8 space-y-8">
      <div>
        <h3 className="text-sm font-bold text-on-surface uppercase tracking-wider mb-2">
          Column Spanning Layout (12-column base)
        </h3>
        <p className="text-xs text-on-surface-variant/60 mb-4">
          Combine different span widths to build sidebar, primary contents, and sidebar layouts.
        </p>
        <Grid cols={12} gap={4}>
          <GridItem span={{ base: 12, md: 3 }}>
            <DemoBox className="bg-secondary/20 text-on-surface border-border">
              Sidebar (Span 3)
            </DemoBox>
          </GridItem>
          <GridItem span={{ base: 12, md: 6 }}>
            <DemoBox className="h-32 bg-primary/10 border-primary/30">
              Primary Viewport Content (Span 6)
            </DemoBox>
          </GridItem>
          <GridItem span={{ base: 12, md: 3 }}>
            <DemoBox className="bg-secondary/20 text-on-surface border-border">
              Context Inspector (Span 3)
            </DemoBox>
          </GridItem>
        </Grid>
      </div>

      <div>
        <h3 className="text-sm font-bold text-on-surface uppercase tracking-wider mb-2">
          Grid Item Offsets
        </h3>
        <p className="text-xs text-on-surface-variant/60 mb-4">
          Use the `offset` prop to push items horizontally.
        </p>
        <Grid cols={3} gap={4}>
          <GridItem>
            <DemoBox>Column 1</DemoBox>
          </GridItem>
          <GridItem offset={3}>
            <DemoBox className="bg-success/10 text-success border-success/30">
              Column 3 (Offset 3 / pushed to the right)
            </DemoBox>
          </GridItem>
        </Grid>
      </div>
    </div>
  ),
};

export const BrandSpacingGaps: Story = {
  render: () => (
    <div className="p-8 space-y-8">
      <div>
        <h3 className="text-sm font-bold text-on-surface uppercase tracking-wider mb-2">
          Dashboard Page Spacing (`gap="page"`)
        </h3>
        <p className="text-xs text-on-surface-variant/60 mb-4">
          Uses WardSeal's global page space token (`var(--space-page)` / 24px) for layouts.
        </p>
        <Grid cols={3} gap="page">
          <DemoBox>Dashboard Card 1</DemoBox>
          <DemoBox>Dashboard Card 2</DemoBox>
          <DemoBox>Dashboard Card 3</DemoBox>
        </Grid>
      </div>

      <div>
        <h3 className="text-sm font-bold text-on-surface uppercase tracking-wider mb-2">
          Section Spacing (`gap="section"`)
        </h3>
        <p className="text-xs text-on-surface-variant/60 mb-4">
          Uses WardSeal's global section space token (`var(--space-section)` / 20px).
        </p>
        <Grid cols={3} gap="section">
          <DemoBox>Section Component A</DemoBox>
          <DemoBox>Section Component B</DemoBox>
          <DemoBox>Section Component C</DemoBox>
        </Grid>
      </div>

      <div>
        <h3 className="text-sm font-bold text-on-surface uppercase tracking-wider mb-2">
          Card Element Spacing (`gap="card"`)
        </h3>
        <p className="text-xs text-on-surface-variant/60 mb-4">
          Uses WardSeal's inner card space token (`var(--space-card)` / 16px).
        </p>
        <Grid cols={3} gap="card">
          <DemoBox>Inner Item 1</DemoBox>
          <DemoBox>Inner Item 2</DemoBox>
          <DemoBox>Inner Item 3</DemoBox>
        </Grid>
      </div>
    </div>
  ),
};
