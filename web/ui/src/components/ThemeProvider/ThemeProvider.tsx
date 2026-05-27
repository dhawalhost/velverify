import * as React from "react";

export type Theme = "dark" | "light";

export interface ThemeProviderProps {
  children: React.ReactNode;
  /**
   * Theme applied on first load when no localStorage value exists.
   * @default "dark"
   */
  defaultTheme?: Theme;
  /**
   * localStorage key used to persist the active theme between sessions.
   * @default "wardseal-ui-theme"
   */
  storageKey?: string;
  /**
   * When set, bypasses localStorage entirely and forces this theme.
   * Useful in Storybook stories, server-side rendering, or embedded
   * iframe contexts where localStorage state could bleed between renders.
   */
  forcedTheme?: Theme;
}

export interface ThemeContextProps {
  theme: Theme;
  setTheme: (theme: Theme) => void;
  toggleTheme: () => void;
}

const ThemeProviderContext = React.createContext<ThemeContextProps | undefined>(undefined);

export function ThemeProvider({
  children,
  defaultTheme = "dark",
  storageKey = "wardseal-ui-theme",
  forcedTheme,
  ...props
}: ThemeProviderProps) {
  const isForced = forcedTheme !== undefined;

  const [theme, setThemeState] = React.useState<Theme>(() => {
    // When forcedTheme is provided, skip localStorage lookup entirely.
    if (isForced) return forcedTheme!;
    return (localStorage.getItem(storageKey) as Theme) || defaultTheme;
  });

  // Keep internal state in sync when forcedTheme prop changes.
  React.useEffect(() => {
    if (isForced) setThemeState(forcedTheme!);
  }, [forcedTheme, isForced]);

  React.useEffect(() => {
    const root = window.document.documentElement;
    root.classList.remove("light", "dark");
    root.classList.add(theme);
    // Only persist to localStorage when not force-overriding.
    if (!isForced) localStorage.setItem(storageKey, theme);
  }, [theme, storageKey, isForced]);

  const setTheme = React.useCallback((newTheme: Theme) => {
    if (isForced) return; // Ignore programmatic changes when theme is forced.
    setThemeState(newTheme);
  }, [isForced]);

  const toggleTheme = React.useCallback(() => {
    if (isForced) return;
    setThemeState((prev) => (prev === "dark" ? "light" : "dark"));
  }, [isForced]);

  const value = React.useMemo(
    () => ({
      theme,
      setTheme,
      toggleTheme,
    }),
    [theme, setTheme, toggleTheme]
  );

  return (
    <ThemeProviderContext.Provider value={value} {...props}>
      {/*
       * Apply the theme class directly on this wrapper div as well as the
       * document root. This ensures CSS variable overrides (`.dark` / `.light`)
       * are scoped correctly in isolated contexts like Storybook iframes where
       * documentElement manipulation may not be sufficient.
       */}
      <div
        data-theme={theme}
        className={`${theme} min-h-screen bg-background text-foreground antialiased font-sans transition-colors duration-200`}
      >
        {children}
      </div>
    </ThemeProviderContext.Provider>
  );
}

export function useTheme() {
  const context = React.useContext(ThemeProviderContext);
  if (context === undefined) {
    throw new Error("useTheme must be used within a ThemeProvider");
  }
  return context;
}
