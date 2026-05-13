import * as React from "react";
import { cn } from "@/lib/utils";

// ── Types ─────────────────────────────────────────────────────────────────────
export interface DataPillProps extends React.HTMLAttributes<HTMLElement> {
    /** The value to display — typically an ID, hash, or technical ref */
    value: string;
    /** Optional lucide icon rendered before the value */
    icon?: React.ReactNode;
    /** Truncate value to N characters (default: full) */
    truncate?: number;
    /** Renders the full value in a tooltip title attribute */
    showTitle?: boolean;
    /** Semantic tag — defaults to <code> */
    as?: "code" | "span" | "div";
}

// ── Component ─────────────────────────────────────────────────────────────────
export const DataPill: React.FC<DataPillProps> = ({
    value,
    icon,
    truncate,
    showTitle = true,
    as: Tag = "code",
    className,
    ...props
}) => {
    const display = truncate ? value.substring(0, truncate) : value;

    return (
        <div className={cn("flex items-center gap-2.5", className)}>
            {icon && (
                <div className="w-7 h-7 flex items-center justify-center bg-surface-container/50 rounded-lg text-on-surface-variant/40">
                    {icon}
                </div>
            )}
            <Tag
                className="font-mono text-[11px] font-bold text-on-surface-variant/40 tracking-tight"
                title={showTitle ? value : undefined}
                {...(props as any)}
            >
                {display}
            </Tag>
        </div>
    );
};
DataPill.displayName = "DataPill";
