import React from 'react';
import { Card, CardHeader, CardTitle, CardContent, CardDescription, CardFooter } from '@/components/ui/card';
import { Table, TableHeader, TableHead, TableRow } from '@/components/ui/table';
import { cn } from '@/lib/utils';

// ── Card ──────────────────────────────────────────────────────────────────────

export const GlassCard = React.forwardRef<HTMLDivElement, React.HTMLAttributes<HTMLDivElement>>(
    ({ className, ...props }, ref) => (
        <Card
            ref={ref}
            className={cn(
                "border-none bg-card/80 backdrop-blur-xl rounded-xl overflow-hidden transition-all duration-200 shadow-card ring-1 ring-on-surface/5",
                className
            )}
            {...props}
        />
    )
);
GlassCard.displayName = "GlassCard";

// ── Card Header ───────────────────────────────────────────────────────────────

export const GlassCardHeader = React.forwardRef<HTMLDivElement, React.HTMLAttributes<HTMLDivElement>>(
    ({ className, ...props }, ref) => (
        <CardHeader
            ref={ref}
            className={cn("bg-transparent border-b border-on-surface/5 p-4 px-6", className)}
            {...props}
        />
    )
);
GlassCardHeader.displayName = "GlassCardHeader";

// ── Card Title ────────────────────────────────────────────────────────────────

export const GlassCardTitle = React.forwardRef<HTMLParagraphElement, React.HTMLAttributes<HTMLHeadingElement>>(
    ({ className, ...props }, ref) => (
        <CardTitle
            ref={ref}
            className={cn(
                "text-base font-bold tracking-tight text-on-surface flex items-center gap-2",
                className
            )}
            {...props}
        />
    )
);
GlassCardTitle.displayName = "GlassCardTitle";

// ── Card Content ──────────────────────────────────────────────────────────────

export const GlassCardContent = React.forwardRef<HTMLDivElement, React.HTMLAttributes<HTMLDivElement>>(
    ({ className, ...props }, ref) => (
        <CardContent ref={ref} className={cn("p-6", className)} {...props} />
    )
);
GlassCardContent.displayName = "GlassCardContent";

// ── Card Description ──────────────────────────────────────────────────────────

export const GlassCardDescription = React.forwardRef<HTMLParagraphElement, React.HTMLAttributes<HTMLParagraphElement>>(
    ({ className, ...props }, ref) => (
        <CardDescription
            ref={ref}
            className={cn("text-[11px] font-medium text-on-surface-variant/60 italic", className)}
            {...props}
        />
    )
);
GlassCardDescription.displayName = "GlassCardDescription";

// ── Card Footer ───────────────────────────────────────────────────────────────

export const GlassCardFooter = React.forwardRef<HTMLDivElement, React.HTMLAttributes<HTMLDivElement>>(
    ({ className, ...props }, ref) => (
        <CardFooter
            ref={ref}
            className={cn("px-6 py-4 bg-surface-container/10 border-t border-on-surface/5", className)}
            {...props}
        />
    )
);
GlassCardFooter.displayName = "GlassCardFooter";

// ── Table ─────────────────────────────────────────────────────────────────────

export const GlassTable = React.forwardRef<HTMLTableElement, React.HTMLAttributes<HTMLTableElement>>(
    ({ className, ...props }, ref) => (
        <div className="relative w-full overflow-auto custom-scrollbar">
            <Table ref={ref} className={cn("w-full caption-bottom text-sm", className)} {...props} />
        </div>
    )
);
GlassTable.displayName = "GlassTable";

export const GlassTableHeader = React.forwardRef<HTMLTableSectionElement, React.HTMLAttributes<HTMLTableSectionElement>>(
    ({ className, ...props }, ref) => (
        <TableHeader ref={ref} className={cn("bg-surface-container/5", className)} {...props} />
    )
);
GlassTableHeader.displayName = "GlassTableHeader";

/**
 * Table head cell with the standard Clean Modernist label style baked in.
 * Overridable via `className` as usual.
 */
export const GlassTableHead = React.forwardRef<HTMLTableCellElement, React.ThHTMLAttributes<HTMLTableCellElement>>(
    ({ className, ...props }, ref) => (
        <TableHead
            ref={ref}
            className={cn(
                "font-bold text-[10px] py-2.5 px-6 text-on-surface-variant/40 tracking-tight uppercase",
                className
            )}
            {...props}
        />
    )
);
GlassTableHead.displayName = "GlassTableHead";

export const GlassTableRow = React.forwardRef<HTMLTableRowElement, React.HTMLAttributes<HTMLTableRowElement>>(
    ({ className, ...props }, ref) => (
        <TableRow
            ref={ref}
            className={cn(
                "hover:bg-surface-container/20 border-b border-on-surface/5 transition-colors group",
                className
            )}
            {...props}
        />
    )
);
GlassTableRow.displayName = "GlassTableRow";
