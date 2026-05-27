# Identity Platform Design System & Constraints

1. THEME: Strict Dark Mode. Default background is `bg-zinc-950`, text is `text-zinc-50`.
2. ACCESSIBILITY (WCAG 2.1 AA): High contrast is mandatory. All interactive elements (buttons, inputs, links) MUST have explicit keyboard focus states using Tailwind's `focus-visible:ring-2` and `focus-visible:ring-offset-2`. Include `aria-labels` on all icon-only buttons.
3. SUSTAINABILITY (Performance): Lean code only. Zero decorative images. Use `lucide-react` for lightweight SVG icons. Do NOT import heavy animation libraries (like Three.js).
4. MOTION: Micro-interactions only. Apply a strict 150ms `ease-in-out` transition to button hovers. Use basic CSS keyframes for loading spinners. No scroll-jacking or page-level transition animations.