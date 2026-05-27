import type { Meta, StoryObj } from "@storybook/react";
import React from "react";
import { Progress } from "./Progress";

const meta: Meta<typeof Progress> = {
  title: "Components/Progress",
  component: Progress,
  tags: ["autodocs"],
};

export default meta;
type Story = StoryObj<typeof Progress>;

export const Default: Story = {
  render: () => {
    const [val, setVal] = React.useState(0);

    React.useEffect(() => {
      const interval = setInterval(() => {
        setVal((v) => (v >= 100 ? 0 : v + 5));
      }, 300);
      return () => clearInterval(interval);
    }, []);

    return (
      <div className="space-y-4 max-w-sm">
        <div className="flex justify-between items-center text-xs font-bold font-mono">
          <span className="text-on-surface-variant/40 uppercase tracking-wider">Syncing Nodes...</span>
          <span className="text-primary">{val}%</span>
        </div>
        <Progress value={val} />
      </div>
    );
  },
};
