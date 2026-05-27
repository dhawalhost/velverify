# @dhawalhost/wardseal-ui-kit

> WardSeal Brand UI Component Library — React 18 + Tailwind CSS, dual-theme (dark/light), built on Radix UI primitives.

## Install

Requires a `.npmrc` in your project root authenticating to GitHub Packages:

```ini
# .npmrc
@dhawalhost:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=${NPM_TOKEN}
```

Then install:

```bash
npm install @dhawalhost/wardseal-ui-kit
```

> `NPM_TOKEN` must be a GitHub Personal Access Token with **`read:packages`** scope. For CI, use `${{ secrets.GITHUB_TOKEN }}`.

## Peer Dependencies

```bash
npm install react react-dom lucide-react boring-avatars
```

## Publish

The package is published to GitHub Packages from [publish-ui.yml](../../.github/workflows/publish-ui.yml) when a tag matching `ui/v*` is pushed.

```bash
git tag ui/v0.1.0
git push origin ui/v0.1.0
```

For local verification before pushing a tag:

```bash
npm run build
npm pack --dry-run
```

## Quick Start

### 1. Import the CSS (main entry file)

```tsx
// src/main.tsx
import '@dhawalhost/wardseal-ui-kit/styles.css';
```

### 2. Add Inter font (index.html)

```html
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet" />
```

### 3. Configure Tailwind

```js
// tailwind.config.js
import { tailwindPreset } from '@dhawalhost/wardseal-ui-kit';

export default {
  darkMode: ['class'],
  content: [
    './src/**/*.{js,ts,jsx,tsx}',
    './node_modules/@dhawalhost/wardseal-ui-kit/dist/**/*.{js,cjs}',
  ],
  presets: [tailwindPreset],
};
```

### 4. Wrap with ThemeProvider

```tsx
import { ThemeProvider } from '@dhawalhost/wardseal-ui-kit';

export default function App() {
  return (
    <ThemeProvider defaultTheme="dark">
      {/* your app */}
    </ThemeProvider>
  );
}
```

### 5. Use components

```tsx
import { Button, Card, CardContent, Badge, Logo } from '@dhawalhost/wardseal-ui-kit';

function Page() {
  return (
    <Card>
      <CardContent className="p-6 flex items-center gap-4">
        <Logo variant="icon" className="h-8 w-8" />
        <Badge variant="success">Active</Badge>
        <Button variant="primary">Get Started</Button>
      </CardContent>
    </Card>
  );
}
```

## Components

| Category | Components |
| --- | --- |
| **Primitives** | Button, Input, Label, Checkbox, Switch, Select, Separator, Skeleton, Progress |
| **Overlays** | Dialog, Sheet, Toast, Tooltip, Popover, Dropdown |
| **Data** | Table, GlassTable, Tabs, ScrollArea, Accordion |
| **Feedback** | Badge, Avatar |
| **Navigation** | CommandMenu |
| **Layout** | Grid, GridItem, PageHeader, AdminShell, PortalLayout |
| **Forms** | FormField, FormGroup, FormSection |
| **Brand** | Logo (icon + full) |
| **Theme** | ThemeProvider, useTheme |

## Theming

The library supports **dark** (default, Electric Neon Green) and **light** (Deep Accessible Emerald) modes via CSS variable token switching.

```tsx
import { useTheme } from '@dhawalhost/wardseal-ui-kit';

function ThemeToggle() {
  const { theme, toggleTheme } = useTheme();
  return <button onClick={toggleTheme}>Switch to {theme === 'dark' ? 'Light' : 'Dark'}</button>;
}
```

For stories and iframes where localStorage state may bleed, use `forcedTheme`:

```tsx
<ThemeProvider forcedTheme="light">...</ThemeProvider>
```

## Versioning

This package follows [Semantic Versioning](https://semver.org/).

| Range | Changes |
| --- | --- |
| Patch (`0.1.x`) | Bug fixes, style tweaks |
| Minor (`0.x.0`) | New components, non-breaking additions |
| Major (`x.0.0`) | Breaking API or token changes |

---

Built with ❤️ by the WardSeal Platform Team.
