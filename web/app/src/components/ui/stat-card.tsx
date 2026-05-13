import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";
import { GlassCard, GlassCardContent } from "@/components/layout/GlassCard";

// ── Variants ──────────────────────────────────────────────────────────────────
const statCardVariants = cva(
    "border-none overflow-hidden rounded-[24px]",
    {
        variants: {
            variant: {
                default: "shadow-xl shadow-on-surface/5 bg-card",
                danger:  "shadow-xl shadow-destructive/5 bg-destructive/10",
                primary: "shadow-xl shadow-primary/5 bg-primary/5",
                success: "shadow-xl shadow-emerald-500/5 bg-success-subtle",
                warning: "shadow-xl shadow-amber-500/5 bg-amber-50",
                muted:   "shadow-xl shadow-on-surface/5 bg-surface-container/10",
            },
        },
        defaultVariants: { variant: "default" },
    }
);

const statValueVariants = cva("text-4xl font-bold tracking-tight leading-none", {
    variants: {
        variant: {
            default: "text-on-surface",
            danger:  "text-destructive",
            primary: "text-primary",
            success: "text-success",
            warning: "text-amber-600",
            muted:   "text-on-surface",
        },
    },
    defaultVariants: { variant: "default" },
});

const statLabelVariants = cva("text-[12px] font-bold tracking-tight leading-none", {
    variants: {
        variant: {
            default: "text-on-surface-variant/40",
            danger:  "text-destructive/40",
            primary: "text-primary/60",
            success: "text-success/60",
            warning: "text-amber-600/60",
            muted:   "text-on-surface-variant/40",
        },
    },
    defaultVariants: { variant: "default" },
});

// ── Types ─────────────────────────────────────────────────────────────────────
export interface StatCardProps
    extends React.HTMLAttributes<HTMLDivElement>,
        VariantProps<typeof statCardVariants> {
    /** Short label shown above the value */
    label: React.ReactNode;
    /** The primary metric value */
    value: React.ReactNode;
    /** Optional lucide icon shown next to the value */
    icon?: React.ReactNode;
    /** Optional secondary/sub-value text shown below */
    subtext?: React.ReactNode;
    /** Whether data is still loading */
    loading?: boolean;
}

// ── Component ─────────────────────────────────────────────────────────────────
export const StatCard = React.forwardRef<HTMLDivElement, StatCardProps>(
    ({ className, variant, label, value, icon, subtext, loading = false, ...props }, ref) => {
        return (
            <GlassCard ref={ref} className={cn(statCardVariants({ variant }), className)} {...props}>
                <GlassCardContent className="p-8">
                    <div className="flex flex-col gap-2">
                        <span className={statLabelVariants({ variant })}>{label}</span>
                        <div className="mt-4 flex items-end gap-3 leading-none">
                            <span className={statValueVariants({ variant })}>
                                {loading ? (
                                    <span className="opacity-20 animate-pulse">—</span>
                                ) : (
                                    value
                                )}
                            </span>
                            {icon && (
                                <span className="opacity-20 mb-0.5">{icon}</span>
                            )}
                        </div>
                        {subtext && (
                            <p className="text-[11px] font-medium text-on-surface-variant/40 mt-2 italic">
                                {subtext}
                            </p>
                        )}
                    </div>
                </GlassCardContent>
            </GlassCard>
        );
    }
);
StatCard.displayName = "StatCard";
