import { createContext, useContext, useEffect, useState } from "react";

// ── Types ─────────────────────────────────────────────────────────────────────
type Theme = "dark" | "light" | "system";

type ThemeProviderProps = {
    children: React.ReactNode;
    defaultTheme?: Theme;
    storageKey?: string;
};

type ThemeProviderState = {
    theme: Theme;
    resolvedTheme: "dark" | "light";
    setTheme: (theme: Theme) => void;
};

// ── Context ───────────────────────────────────────────────────────────────────
const initialState: ThemeProviderState = {
    theme: "light",
    resolvedTheme: "light",
    setTheme: () => null,
};

const ThemeProviderContext = createContext<ThemeProviderState>(initialState);

// ── Provider ──────────────────────────────────────────────────────────────────
export function ThemeProvider({
    children,
    defaultTheme = "light",
    storageKey = "wardseal-theme",
}: ThemeProviderProps) {
    const [theme, setThemeState] = useState<Theme>(
        () => (localStorage.getItem(storageKey) as Theme) ?? defaultTheme
    );

    const [resolvedTheme, setResolvedTheme] = useState<"dark" | "light">("light");

    useEffect(() => {
        const root = window.document.documentElement;
        root.classList.remove("light", "dark");

        if (theme === "system") {
            const systemTheme = window.matchMedia("(prefers-color-scheme: dark)").matches
                ? "dark"
                : "light";
            root.classList.add(systemTheme);
            setResolvedTheme(systemTheme);
            return;
        }

        root.classList.add(theme);
        setResolvedTheme(theme);
    }, [theme]);

    // Listen for OS-level preference changes when theme === "system"
    useEffect(() => {
        if (theme !== "system") return;
        const mq = window.matchMedia("(prefers-color-scheme: dark)");
        const handler = (e: MediaQueryListEvent) => {
            const root = window.document.documentElement;
            root.classList.remove("light", "dark");
            root.classList.add(e.matches ? "dark" : "light");
            setResolvedTheme(e.matches ? "dark" : "light");
        };
        mq.addEventListener("change", handler);
        return () => mq.removeEventListener("change", handler);
    }, [theme]);

    const value: ThemeProviderState = {
        theme,
        resolvedTheme,
        setTheme: (newTheme: Theme) => {
            localStorage.setItem(storageKey, newTheme);
            setThemeState(newTheme);
        },
    };

    return (
        <ThemeProviderContext.Provider value={value}>
            {children}
        </ThemeProviderContext.Provider>
    );
}

// ── Hooks ─────────────────────────────────────────────────────────────────────

/** Access the current theme and setTheme function. */
export const useTheme = () => {
    const context = useContext(ThemeProviderContext);
    if (context === undefined) {
        throw new Error("useTheme must be used within a ThemeProvider");
    }
    return context;
};

/**
 * Returns `true` when the resolved (effective) theme is dark.
 * Useful for conditionally rendering icons or chart colors.
 */
export const useIsDark = () => useTheme().resolvedTheme === "dark";
