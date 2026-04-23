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

                // ── Surface scale ──
                surface: {
                    DEFAULT: "hsl(var(--background))",
                    dim: "#dcd8e4",
                    bright: "#fcf8ff",
                    container: {
                        lowest: "#ffffff",
                        low: "#f6f2fe",
                        DEFAULT: "#f0ecf8",
                        high: "#eae6f3",
                        highest: "#e4e1ed",
                    },
                },
                "on-surface": {
                    DEFAULT: "#1b1b23",
                    variant: "#464554",
                },

                // ── Brand colors ──
                primary: {
                    DEFAULT: "hsl(var(--primary))",
                    foreground: "hsl(var(--primary-foreground))",
                    container: "#4338ca",
                    "on-container": "#c1beff",
                },
                secondary: {
                    DEFAULT: "#505f76",
                    foreground: "#ffffff",
                    container: "#d0e1fb",
                    "on-container": "#54647a",
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
                outline: {
                    DEFAULT: "hsl(var(--border))",
                },
            },

            // ── Border radius scale ──
            borderRadius: {
                sm: "var(--radius-sm)",
                DEFAULT: "var(--radius-md)",
                md: "var(--radius-md)",
                lg: "var(--radius-lg)",
                xl: "var(--radius-xl)",
                "2xl": "var(--radius-2xl)",
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
                display: ["Inter", "system-ui", "sans-serif"],
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
