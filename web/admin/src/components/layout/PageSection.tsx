import React from "react";
import { cn } from "@/lib/utils";
import { GlassCard, GlassCardHeader, GlassCardTitle, GlassCardContent } from "./GlassCard";

// ── Types ─────────────────────────────────────────────────────────────────────
export interface PageSectionProps {
    /** Section heading */
    title: string;
    /** Optional lucide icon beside the title */
    icon?: React.ReactNode;
    /** Subtitle / muted description */
    description?: string;
    /** Extra content to render in the header row (e.g. action buttons) */
    headerActions?: React.ReactNode;
    /** Main body content */
    children: React.ReactNode;
    /** No internal padding on the content area (useful for tables) */
    noPadding?: boolean;
    /** Additional classes on the outer GlassCard */
    className?: string;
    /** Additional classes on the content wrapper */
    contentClassName?: string;
}

// ── Component ─────────────────────────────────────────────────────────────────
/**
 * Standard page section: card with header + content.
 * Drop-in for the GlassCard + GlassCardHeader + icon + title + GlassCardContent
 * pattern used in every list/table page.
 *
 * @example
 * <PageSection
 *   title="Request manifest"
 *   icon={<ClipboardList />}
 *   description="Pending access requests awaiting authorization."
 *   headerActions={<Button>Export</Button>}
 *   noPadding
 * >
 *   <GlassTable>...</GlassTable>
 * </PageSection>
 */
export const PageSection: React.FC<PageSectionProps> = ({
    title,
    icon,
    description,
    headerActions,
    children,
    noPadding = false,
    className,
    contentClassName,
}) => {
    return (
        <GlassCard
            className={cn(
                "border-none shadow-2xl shadow-on-surface/5 bg-white overflow-hidden rounded-[32px]",
                className
            )}
        >
            <GlassCardHeader className="py-8 px-10 border-b border-on-surface/5 bg-surface-container/5">
                <div className="flex items-center justify-between">
                    <div className="flex items-center gap-5">
                        {icon && (
                            <div className="p-3.5 bg-primary/5 rounded-2xl text-primary">
                                {icon}
                            </div>
                        )}
                        <div>
                            <GlassCardTitle className="text-2xl font-bold tracking-tight text-on-surface">
                                {title}
                            </GlassCardTitle>
                            {description && (
                                <p className="text-on-surface-variant/60 font-medium text-[11px] mt-1.5 italic">
                                    {description}
                                </p>
                            )}
                        </div>
                    </div>
                    {headerActions && (
                        <div className="flex items-center gap-3">{headerActions}</div>
                    )}
                </div>
            </GlassCardHeader>

            <GlassCardContent className={cn(noPadding ? "p-0" : "p-10", contentClassName)}>
                {children}
            </GlassCardContent>
        </GlassCard>
    );
};
PageSection.displayName = "PageSection";
