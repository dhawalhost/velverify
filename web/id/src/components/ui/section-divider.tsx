import * as React from "react";
import { cn } from "@/lib/utils";

// ── Types ─────────────────────────────────────────────────────────────────────
export interface SectionDividerProps extends React.HTMLAttributes<HTMLDivElement> {
    /** Label rendered inline with the rule */
    label?: string;
    /** Size of the label text */
    size?: "sm" | "md";
}

// ── Component ─────────────────────────────────────────────────────────────────
export const SectionDivider: React.FC<SectionDividerProps> = ({
    label,
    size = "sm",
    className,
    ...props
}) => {
    return (
        <div className={cn("flex items-center gap-6", className)} {...props}>
            {label && (
                <span
                    className={cn(
                        "font-bold tracking-tight text-on-surface-variant/20 italic flex-shrink-0",
                        size === "sm" ? "text-[12px]" : "text-[13px]"
                    )}
                >
                    {label}
                </span>
            )}
            <div className="h-px flex-1 bg-on-surface/5" />
        </div>
    );
};
SectionDivider.displayName = "SectionDivider";
