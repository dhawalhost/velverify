import React from "react";
import { Search, Filter } from "lucide-react";
import { cn } from "@/lib/utils";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";

// ── Types ─────────────────────────────────────────────────────────────────────
export interface FilterBarProps {
    /** Controlled value of the search input */
    value: string;
    /** Change handler */
    onChange: (value: string) => void;
    /** Submit handler (e.g. re-fetch with new filters) */
    onSubmit?: (e?: React.FormEvent) => void;
    /** Placeholder text */
    placeholder?: string;
    /** Label for the submit/filter button */
    submitLabel?: string;
    /** Additional right-side elements (e.g. an Export button) */
    actions?: React.ReactNode;
    /** Additional class on the outer form */
    className?: string;
    /** Whether to show the filter button */
    showFilterButton?: boolean;
    /** Extra filters rendered after the search input */
    extraFilters?: React.ReactNode;
}

// ── Component ─────────────────────────────────────────────────────────────────
/**
 * Standard search + filter bar used at the top of every list page.
 *
 * @example
 * <FilterBar
 *   value={filters.query}
 *   onChange={(v) => setFilters({ ...filters, query: v })}
 *   onSubmit={handleFilterSubmit}
 *   placeholder="Filter by name or ID..."
 *   actions={<Button onClick={handleExport}>Export</Button>}
 * />
 */
export const FilterBar: React.FC<FilterBarProps> = ({
    value,
    onChange,
    onSubmit,
    placeholder = "Filter…",
    submitLabel = "Filter",
    actions,
    className,
    showFilterButton = true,
    extraFilters,
}) => {
    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        onSubmit?.(e);
    };

    return (
        <form
            onSubmit={handleSubmit}
            className={cn(
                "flex flex-col md:flex-row gap-4 w-full",
                className
            )}
        >
            {/* Search input */}
            <div className="flex-1 relative group">
                <Search className="absolute left-4 top-1/2 -translate-y-1/2 h-4 w-4 text-on-surface-variant/40 group-focus-within:text-primary transition-colors pointer-events-none" />
                <Input
                    placeholder={placeholder}
                    className="pl-12 h-12 border-none rounded-2xl bg-card ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 transition-all font-medium"
                    value={value}
                    onChange={(e) => onChange(e.target.value)}
                />
            </div>

            {/* Extra filters slot */}
            {extraFilters}

            {/* Filter submit button */}
            {showFilterButton && (
                <Button
                    type="submit"
                    className="h-12 rounded-2xl px-10 font-bold text-[12px] tracking-tight shadow-sm shadow-primary/10 transition-all shrink-0"
                >
                    <Filter className="mr-2 h-4 w-4" />
                    {submitLabel}
                </Button>
            )}

            {/* Right-side action slot */}
            {actions && (
                <div className="flex items-center gap-3 shrink-0">
                    {actions}
                </div>
            )}
        </form>
    );
};
FilterBar.displayName = "FilterBar";
