import os

css_content = """@tailwind base;
@tailwind components;
@tailwind utilities;

/* ─────────────────────────────────────────────
   WardSeal Design Token System — Strict Dark Mode
   Single source of truth for all UI tokens.
   ───────────────────────────────────────────── */
@layer base {
  :root {
    /* ── Surface system (Zinc-950 Dark) ── */
    --background: 240 6% 4%;
    --foreground: 0 0% 98%;

    --surface: 240 6% 4%;
    --surface-dim: 240 6% 2%;
    --surface-bright: 240 6% 10%;

    --surface-container-lowest: 0 0% 0%;
    --surface-container-low: 240 6% 2%;
    --surface-container: 240 6% 4%;
    --surface-container-high: 240 6% 10%;
    --surface-container-highest: 240 6% 14%;

    --on-surface: 0 0% 98%;
    --on-surface-variant: 240 5% 65%;

    --outline: 240 5% 26%;
    --outline-variant: 240 5% 16%;

    /* ── Dark Brand colors (Electric Green) ── */
    --primary: 158 100% 51%;
    --on-primary: 240 6% 4%;
    --primary-container: 158 100% 25%;
    --on-primary-container: 158 100% 85%;

    --secondary: 240 6% 15%;
    --on-secondary: 0 0% 98%;

    --card: 240 6% 10%;
    --card-foreground: 0 0% 98%;

    --popover: 240 6% 10%;
    --popover-foreground: 0 0% 98%;

    --muted: 240 6% 10%;
    --muted-foreground: 240 5% 65%;

    --accent: 240 6% 15%;
    --accent-foreground: 0 0% 98%;

    --destructive: 0 84.2% 60.2%;
    --destructive-foreground: 210 40% 98%;

    --border: 240 6% 15%;
    --input: 240 6% 15%;
    --ring: 158 100% 51%;

    --surface-inverse: 0 0% 98%;
    --on-surface-inverse: 240 6% 4%;

    /* ── semantic state colors ── */
    --success: 152 69% 31%;
    --success-foreground: 0 0% 100%;
    --success-subtle: 145 40% 14%;

    --warning: 37 91% 40%;
    --warning-foreground: 0 0% 100%;
    --warning-subtle: 48 60% 12%;

    --error: 0 75% 41%;
    --error-foreground: 0 0% 100%;
    --error-subtle: 0 50% 14%;

    /* ── shadow tokens ── */
    --shadow-xs: 0 1px 2px 0 rgb(0 0 0 / 0.04);
    --shadow-sm: 0 4px 16px -4px rgb(0 0 0 / 0.06);
    --shadow-card: 0 8px 32px -8px rgb(0 0 0 / 0.4);
    --shadow-overlay: 0 24px 64px -12px rgb(0 0 0 / 0.6);

    /* ── scale ── */
    --radius: 6px;
    --radius-sm: 4px;
    --radius-md: 6px;
    --radius-lg: 8px;
    --radius-xl: 12px;

    --space-page: 24px;
    --space-section: 20px;
    --space-card: 16px;

    --font-display: 'Inter', system-ui, sans-serif;
  }
}

@layer base {
  * {
    @apply border-border;
  }

  body {
    @apply bg-background text-foreground;
    font-family: var(--font-display);
    font-feature-settings: "cv02", "cv03", "cv04", "cv11";
    -webkit-font-smoothing: antialiased;
  }
}

@layer utilities {
  .custom-scrollbar {
    scrollbar-width: thin;
    scrollbar-color: hsl(var(--border)) transparent;
  }

  .custom-scrollbar::-webkit-scrollbar {
    width: 4px;
    height: 4px;
  }

  .custom-scrollbar::-webkit-scrollbar-thumb {
    background-color: hsl(var(--border));
    border-radius: 999px;
  }

  .glass-card {
    @apply relative overflow-hidden rounded-[var(--radius)] border bg-black/40 border-white/5 backdrop-blur-xl;
  }

  .glass-header {
    @apply bg-black/20 backdrop-blur-md;
  }
}
"""

mfes = ["admin", "app", "developer", "status", "id"]

for mfe in mfes:
    css_path = f"{mfe}/src/index.css"
    if os.path.exists(css_path):
        with open(css_path, "w") as f:
            f.write(css_content)
        print(f"Updated {css_path}")

    btn_path = f"{mfe}/src/components/ui/button.tsx"
    if os.path.exists(btn_path):
        with open(btn_path, "r") as f:
            btn_content = f.read()
        
        # Replace transition-colors with transition-all duration-150 ease-in-out
        # and ensure ring is there
        btn_content = btn_content.replace(
            "transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2",
            "transition-all duration-150 ease-in-out focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
        )
        
        with open(btn_path, "w") as f:
            f.write(btn_content)
        print(f"Updated {btn_path}")

