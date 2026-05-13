import * as React from "react";
import { cn } from "@/lib/utils";
import { TableRow, TableCell } from "@/components/ui/table";

// ── Types ─────────────────────────────────────────────────────────────────────
export interface EmptyStateProps extends React.HTMLAttributes<HTMLDivElement> {
    /** Lucide icon to display */
    icon?: React.ReactNode;
    /** Primary empty-state message */
    message?: string;
    /** Optional secondary hint text */
    hint?: string;
    /** Optional action button/element */
    action?: React.ReactNode;
    /** For use inside a <tbody>: wraps in a <tr><td colSpan={n}> */
    asTableRow?: boolean;
    /** Number of columns to span when asTableRow is true */
    colSpan?: number;
}

// ── Standalone ────────────────────────────────────────────────────────────────
const EmptyStateContent: React.FC<Omit<EmptyStateProps, "asTableRow" | "colSpan">> = ({
    className,
    icon,
    message = "No data found.",
    hint,
    action,
    ...props
}) => (
    <div
        className={cn(
            "flex flex-col items-center justify-center gap-6 py-32 text-center",
            className
        )}
        {...props}
    >
        {icon && (
            <div className="opacity-15 text-on-surface-variant">
                {icon}
            </div>
        )}
        <div className="space-y-2">
            <p className="text-sm font-medium text-on-surface-variant/40 italic">
                {message}
            </p>
            {hint && (
                <p className="text-[11px] font-medium text-on-surface-variant/20 italic">
                    {hint}
                </p>
            )}
        </div>
        {action}
    </div>
);

// ── Main export (handles both standalone and table-row modes) ─────────────────
export const EmptyState = React.forwardRef<HTMLDivElement, EmptyStateProps>(
    ({ asTableRow = false, colSpan = 6, ...props }, ref) => {
        if (asTableRow) {
            return (
                <TableRow className="hover:bg-transparent border-none">
                    <TableCell colSpan={colSpan} className="p-0">
                        <EmptyStateContent {...props} />
                    </TableCell>
                </TableRow>
            );
        }

        return (
            <div ref={ref}>
                <EmptyStateContent {...props} />
            </div>
        );
    }
);
EmptyState.displayName = "EmptyState";
