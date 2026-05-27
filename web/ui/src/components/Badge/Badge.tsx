import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "../../lib/utils";

const badgeVariants = cva(
  "inline-flex items-center rounded-md border px-2.5 py-0.5 text-xs font-bold tracking-tight transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 border-none shadow-none",
  {
    variants: {
      variant: {
        default: "bg-surface-container-high text-on-surface hover:bg-surface-container-highest",
        primary: "bg-primary/10 text-primary hover:bg-primary/20",
        secondary: "bg-secondary text-on-secondary hover:bg-secondary/80",
        success: "bg-success-subtle text-success hover:bg-success-subtle/80",
        warning: "bg-warning-subtle text-warning hover:bg-warning-subtle/80",
        error: "bg-error-subtle text-error hover:bg-error-subtle/80",
        destructive: "bg-destructive/10 text-destructive hover:bg-destructive/20",
        neutral: "bg-surface-container-high text-on-surface-variant/75 hover:bg-surface-container-highest",
        outline: "border border-border text-on-surface bg-transparent hover:bg-accent",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  }
);

export interface BadgeProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return (
    <div className={cn(badgeVariants({ variant }), className)} {...props} />
  );
}

export { Badge, badgeVariants };
