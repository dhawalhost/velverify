/** @type {import('tailwindcss').Config} */
export default {
    darkMode: ["class"],
    content: [
        "./index.html",
        "./src/**/*.{js,ts,jsx,tsx}",
    ],
    theme: {
        extend: {
            colors: {
                border: "hsl(var(--border))",
                input: "hsl(var(--input))",
                ring: "hsl(var(--ring))",
                background: "hsl(var(--background))",
                foreground: "hsl(var(--foreground))",

                // ── Surface scale (Theming enabled) ──
                surface: {
                    DEFAULT: "hsl(var(--surface))",
                    dim: "hsl(var(--surface-dim))",
                    bright: "hsl(var(--surface-bright))",
                    container: {
                        lowest: "hsl(var(--surface-container-lowest))",
                        low: "hsl(var(--surface-container-low))",
                        DEFAULT: "hsl(var(--surface-container))",
                        high: "hsl(var(--surface-container-high))",
                        highest: "hsl(var(--surface-container-highest))",
                    },
                },
                "on-surface": {
                    DEFAULT: "hsl(var(--on-surface))",
                    variant: "hsl(var(--on-surface-variant))",
                },
                inverse: "hsl(var(--surface-inverse))",
                "on-inverse": "hsl(var(--on-surface-inverse))",
                outline: {
                    DEFAULT: "hsl(var(--outline))",
                    variant: "hsl(var(--outline-variant))",
                },

                // ── Brand colors ──
                primary: {
                    DEFAULT: "hsl(var(--primary))",
                    foreground: "hsl(var(--on-primary))",
                    container: "hsl(var(--primary-container))",
                    "on-container": "hsl(var(--on-primary-container))",
                },
                secondary: {
                    DEFAULT: "hsl(var(--secondary))",
                    foreground: "hsl(var(--on-secondary))",
                    container: "hsl(var(--secondary-container))",
                    "on-container": "hsl(var(--on-secondary-container))",
                },

                // ── Semantic state colors ──
                success: {
                    DEFAULT: "hsl(var(--success))",
                    foreground: "hsl(var(--success-foreground))",
                    subtle: "hsl(var(--success-subtle))",
                },
                warning: {
                    DEFAULT: "hsl(var(--warning))",
                    foreground: "hsl(var(--warning-foreground))",
                    subtle: "hsl(var(--warning-subtle))",
                },
                error: {
                    DEFAULT: "hsl(var(--error))",
                    foreground: "hsl(var(--error-foreground))",
                    subtle: "hsl(var(--error-subtle))",
                },
                info: {
                    DEFAULT: "hsl(var(--info))",
                    foreground: "hsl(var(--info-foreground))",
                    subtle: "hsl(var(--info-subtle))",
                },

                // ── shadcn compat ──
                destructive: {
                    DEFAULT: "hsl(var(--destructive))",
                    foreground: "hsl(var(--destructive-foreground))",
                },
                muted: {
                    DEFAULT: "hsl(var(--muted))",
                    foreground: "hsl(var(--muted-foreground))",
                },
                accent: {
                    DEFAULT: "hsl(var(--accent))",
                    foreground: "hsl(var(--accent-foreground))",
                },
                popover: {
                    DEFAULT: "hsl(var(--popover))",
                    foreground: "hsl(var(--popover-foreground))",
                },
                card: {
                    DEFAULT: "hsl(var(--card))",
                    foreground: "hsl(var(--card-foreground))",
                },
            },

            // ── Border radius scale ──
            borderRadius: {
                sm: "var(--radius-sm)",
                DEFAULT: "var(--radius-md)",
                md: "var(--radius-md)",
                lg: "var(--radius-lg)",
                xl: "var(--radius-xl)",
                "2xl": "32px",
                "3xl": "40px",
            },

            // ── Box shadow scale ──
            boxShadow: {
                xs: "var(--shadow-xs)",
                sm: "var(--shadow-sm)",
                card: "var(--shadow-card)",
                overlay: "var(--shadow-overlay)",
            },

            // ── Font families ──
            fontFamily: {
                sans: ["Inter", "system-ui", "sans-serif"],
                mono: ["JetBrains Mono", "Fira Code", "ui-monospace", "monospace"],
            },

            // ── Font sizes ──
            fontSize: {
                detail: ["10px", { lineHeight: "1.4", letterSpacing: "-0.01em" }],
                label:  ["11px", { lineHeight: "1.4", letterSpacing: "-0.01em", fontWeight: "700" }],
                caption:["12px", { lineHeight: "1.5", letterSpacing: "-0.01em" }],
                body:   ["14px", { lineHeight: "1.5" }],
                "body-lg": ["16px", { lineHeight: "1.5" }],
                heading: ["20px", { lineHeight: "1.3", letterSpacing: "-0.02em", fontWeight: "700" }],
                title:  ["24px", { lineHeight: "1.25", letterSpacing: "-0.02em", fontWeight: "700" }],
                hero:   ["32px", { lineHeight: "1.1", letterSpacing: "-0.03em", fontWeight: "800" }],
            },

            // ── Spacing tokens ──
            spacing: {
                page: "var(--space-page)",
                section: "var(--space-section)",
                card: "var(--space-card)",
            },

            // ── keyframes ──
            keyframes: {
                "fade-in": {
                    "0%":   { opacity: "0" },
                    "100%": { opacity: "1" },
                },
                "slide-up": {
                    "0%":   { opacity: "0", transform: "translateY(8px)" },
                    "100%": { opacity: "1", transform: "translateY(0)" },
                },
                "scale-in": {
                    "0%":   { opacity: "0", transform: "scale(0.96)" },
                    "100%": { opacity: "1", transform: "scale(1)" },
                },
            },
            animation: {
                "fade-in":  "fade-in 0.3s ease-out",
                "slide-up": "slide-up 0.3s ease-out",
                "scale-in": "scale-in 0.2s ease-out",
            },
        },
    },
    plugins: [],
};
