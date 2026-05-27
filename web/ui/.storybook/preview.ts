import type { Preview } from "@storybook/react";
import "../src/styles/global.css";

const preview: Preview = {
  parameters: {
    controls: {
      matchers: {
        color: /(background|color)$/i,
        date: /Date$/i,
      },
    },
    backgrounds: {
      // Disable Storybook's built-in background switcher — our ThemeProvider
      // controls the canvas background via CSS variables on the wrapper div.
      disable: true,
    },
  },
  decorators: [
    (Story) => {
      // Stamp the `dark` class on the Storybook iframe's <html> element so
      // that :root / .dark CSS variable tokens always apply correctly for any
      // story that is NOT wrapped in a ThemeProvider (e.g. Button, Badge, etc).
      if (typeof document !== "undefined") {
        document.documentElement.classList.remove("light", "dark");
        document.documentElement.classList.add("dark");
        document.body.style.background = "hsl(240 6% 4%)";
      }
      return Story();
    },
  ],
};

export default preview;
