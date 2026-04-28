/**
 * WardSeal Design Token Constants — Clean Modernist
 *
 * Use these in places where CSS classes are insufficient:
 * - Recharts / D3 fill/stroke props
 * - Dynamic style objects
 * - Programmatic class selection
 *
 * All values mirror the CSS custom properties in index.css.
 */

// ── Color tokens ──────────────────────────────────────────────────────────────
export const colors = {
    primary:   "hsl(var(--primary))",
    success:   "hsl(var(--success))",
    warning:   "hsl(var(--warning))",
    error:     "hsl(var(--destructive))",
    info:      "hsl(var(--primary))",

    // Surface
    surface:           "hsl(var(--background))",
    surfaceContainer:  "hsl(var(--surface-container))",
    surfaceContainerLow: "hsl(var(--surface-container-low))",
    onSurface:         "hsl(var(--on-surface))",
    onSurfaceVariant:  "hsl(var(--on-surface-variant))",

    // Chart palette (8 harmonious hues)
    chart: [
        "hsl(var(--primary))",   // primary indigo
        "hsl(217 91% 55%)",      // vibrant blue
        "hsl(152 69% 40%)",      // emerald
        "hsl(37 91% 50%)",       // amber
        "hsl(271 76% 53%)",      // violet
        "hsl(0 84% 60%)",        // red
        "hsl(198 85% 48%)",      // cyan
        "hsl(325 78% 56%)",      // pink
    ],
} as const;

// ── Border radius tokens ──────────────────────────────────────────────────────
export const radii = {
    sm:      "8px",
    md:      "12px",
    lg:      "16px",
    xl:      "24px",
    card:    "32px",
    overlay: "40px",
    pill:    "999px",
} as const;

// ── Shadow tokens ─────────────────────────────────────────────────────────────
export const shadows = {
    xs:      "var(--shadow-xs)",
    sm:      "var(--shadow-sm)",
    card:    "var(--shadow-card)",
    overlay: "var(--shadow-overlay)",
} as const;

// ── Typography tokens ─────────────────────────────────────────────────────────
export const typography = {
    // Font sizes
    sizes: {
        detail:  "10px",
        label:   "11px",
        caption: "12px",
        body:    "14px",
        heading: "20px",
        title:   "24px",
        hero:    "32px",
    },
    // Standard class strings (compose with cn())
    classes: {
        /** Field labels, table headers */
        label:    "text-[12px] font-bold tracking-tight text-on-surface-variant/40",
        /** Metadata, timestamps, IDs */
        detail:   "text-[11px] font-medium text-on-surface-variant/40 italic",
        /** Standard table cell content */
        cell:     "text-sm font-bold tracking-tight text-on-surface",
        /** Card / section titles */
        heading:  "text-2xl font-bold tracking-tight text-on-surface",
        /** Page-level titles */
        page:     "text-3xl font-bold tracking-tight text-on-surface",
        /** Muted description text */
        muted:    "text-[11px] font-medium text-on-surface-variant/60 italic",
    },
} as const;

// ── Spacing tokens ────────────────────────────────────────────────────────────
export const spacing = {
    page:    "40px",
    section: "32px",
    card:    "24px",
    row:     "24px",
} as const;

// ── Animation presets (for recharts / motion) ─────────────────────────────────
export const animation = {
    /** Standard page transition */
    fadeIn: { duration: 300, easing: "ease-out" },
    /** Chart entry */
    chartEntry: { duration: 500, easing: "ease-out" },
} as const;

// ── Chart config helpers ──────────────────────────────────────────────────────
/** Standard recharts tooltip style */
export const chartTooltipStyle = {
    contentStyle: {
        backgroundColor: "hsl(var(--card))",
        borderRadius: radii.card,
        border: "none",
        boxShadow: "0 10px 40px -10px hsla(var(--on-surface)/0.2)",
        padding: "16px",
    },
    itemStyle:  { color: colors.primary, fontWeight: "bold", fontSize: "12px" },
    labelStyle: { color: colors.onSurfaceVariant, fontWeight: "bold", fontSize: "10px", marginBottom: "8px" },
    cursor:     { stroke: colors.primary, strokeWidth: 2, strokeDasharray: "4 4" },
} as const;

/** Standard recharts CartesianGrid style */
export const chartGridStyle = {
    strokeDasharray: "8 8",
    vertical: false,
    stroke: "hsl(var(--on-surface)/.05)",
} as const;

/** Standard recharts axis tick style */
export const chartAxisTickStyle = {
    fontSize: 10,
    fontWeight: 700,
    fill: "hsl(var(--on-surface-variant)/.4)",
} as const;
