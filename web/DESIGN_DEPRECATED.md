---
name: Clean Modernist Security
colors:
  surface: '#fcf8ff'
  surface-dim: '#dcd8e4'
  surface-bright: '#fcf8ff'
  surface-container-lowest: '#ffffff'
  surface-container-low: '#f6f2fe'
  surface-container: '#f0ecf8'
  surface-container-high: '#eae6f3'
  surface-container-highest: '#e4e1ed'
  on-surface: '#1b1b23'
  on-surface-variant: '#464554'
  inverse-surface: '#302f39'
  inverse-on-surface: '#f3effb'
  outline: '#777586'
  outline-variant: '#c7c4d7'
  surface-tint: '#5148d7'
  primary: '#2a14b4'
  on-primary: '#ffffff'
  primary-container: '#4338ca'
  on-primary-container: '#c1beff'
  inverse-primary: '#c3c0ff'
  secondary: '#505f76'
  on-secondary: '#ffffff'
  secondary-container: '#d0e1fb'
  on-secondary-container: '#54647a'
  tertiary: '#692400'
  on-tertiary: '#ffffff'
  tertiary-container: '#8f3400'
  on-tertiary-container: '#ffb393'
  error: '#ba1a1a'
  on-error: '#ffffff'
  error-container: '#ffdad6'
  on-error-container: '#93000a'
  primary-fixed: '#e3dfff'
  primary-fixed-dim: '#c3c0ff'
  on-primary-fixed: '#100069'
  on-primary-fixed-variant: '#372abf'
  secondary-fixed: '#d3e4fe'
  secondary-fixed-dim: '#b7c8e1'
  on-secondary-fixed: '#0b1c30'
  on-secondary-fixed-variant: '#38485d'
  tertiary-fixed: '#ffdbcd'
  tertiary-fixed-dim: '#ffb597'
  on-tertiary-fixed: '#360f00'
  on-tertiary-fixed-variant: '#7d2d00'
  background: '#fcf8ff'
  on-background: '#1b1b23'
  surface-variant: '#e4e1ed'
typography:
  display-lg:
    fontFamily: Inter
    fontSize: 36px
    fontWeight: '600'
    lineHeight: '1.2'
    letterSpacing: -0.02em
  headline-md:
    fontFamily: Inter
    fontSize: 24px
    fontWeight: '600'
    lineHeight: '1.3'
    letterSpacing: -0.01em
  body-base:
    fontFamily: Inter
    fontSize: 16px
    fontWeight: '400'
    lineHeight: '1.6'
    letterSpacing: '0'
  body-sm:
    fontFamily: Inter
    fontSize: 14px
    fontWeight: '400'
    lineHeight: '1.5'
    letterSpacing: '0'
  label-caps:
    fontFamily: Inter
    fontSize: 12px
    fontWeight: '600'
    lineHeight: '1'
    letterSpacing: 0.05em
rounded:
  sm: 0.25rem
  DEFAULT: 0.5rem
  md: 0.75rem
  lg: 1rem
  xl: 1.5rem
  full: 9999px
spacing:
  unit: 4px
  xs: 4px
  sm: 8px
  md: 16px
  lg: 24px
  xl: 40px
  container-max: 1440px
  gutter: 24px
---

## Brand & Style
The design system is rooted in the "Clean Modernist" movement, specifically tailored for the high-stakes environment of enterprise security. The brand personality is defined by clinical precision, quiet confidence, and absolute clarity. It avoids the "dark hacker" tropes of traditional security software in favor of an airy, accessible aesthetic that reduces cognitive load and promotes rapid decision-making.

The target audience consists of security analysts and C-suite executives who require high-density information without the visual noise. By utilizing significant whitespace and a restricted color palette, the UI evokes an emotional response of organized calm and professional reliability. The style is strictly **Minimalist**, prioritizing functional utility and structural integrity over decorative elements.

## Colors
This design system employs a light-mode-first palette to maximize readability and create a sense of openness. The core background is pure white (#FFFFFF), while a subtle off-white (#F8FAFC) is used to differentiate container surfaces and sidebars.

The primary accent is a **Deep Indigo (#4338CA)**, selected for its association with trust, intelligence, and stability. This color is used sparingly for primary actions and critical status indicators. Neutrals are derived from a cool slate scale, ensuring that borders and text maintain high legibility without introducing unnecessary warmth or distraction. Success, warning, and error states should utilize desaturated versions of green, amber, and red to maintain the system's sophisticated tone.

## Typography
**Inter** is the sole typeface for the design system, chosen for its exceptional legibility in data-heavy interfaces. The typographic hierarchy relies on deliberate shifts in weight and scale rather than color. 

Headlines use semi-bold weights with slight negative letter-spacing to appear compact and authoritative. Body text is set with generous line-height to ensure long-form reports are easy to scan. Small labels and metadata utilize an uppercase style with increased letter-spacing to provide clear distinction from interactive elements. All text should adhere to strict contrast ratios to ensure accessibility across the platform.

## Layout & Spacing
The design system utilizes a **Fluid Grid** model built on a 4px baseline unit. For main application views, a 12-column grid is employed with 24px gutters, allowing content to breathe while maintaining structural alignment.

Margins are generous, typically starting at 24px for page edges, ensuring that information never feels cramped against the viewport. Vertical rhythm is maintained by using consistent multiples of the 4px unit (16px, 24px, 40px) to separate distinct sections and components. This creates a predictable flow that guides the user's eye naturally through complex security workflows.

## Elevation & Depth
In alignment with Modernist principles, the design system rejects heavy shadows in favor of **Low-contrast outlines** and **Tonal layers**. Depth is communicated through subtle 1px borders (#E2E8F0) and varying background shades rather than artificial light sources.

When an element must appear "raised" (such as a dropdown menu or a modal), a single, highly diffused ambient shadow is used: `0px 4px 20px rgba(0, 0, 0, 0.05)`. This ensures the UI remains "flat" and "airy," preventing the interface from feeling heavy or dated. Layering is achieved by placing white cards on the off-white background (#F8FAFC), creating a clear but soft distinction of hierarchy.

## Shapes
The shape language of the design system is defined by a consistent **ROUND_TWELVE (12px)** radius for all primary containers, cards, and input fields. This specific level of roundness strikes a balance between the rigid "industrial" feel of sharp corners and the "playful" feel of pill shapes.

Buttons and smaller interactive components follow this 12px standard (represented as `rounded-lg` in the variable scaling), while smaller utility items like tags or checkboxes may scale down to 4px or 8px to maintain visual harmony. This consistency in geometry reinforces the platform's professional and modern identity.

## Components
- **Buttons:** Primary buttons use the Deep Indigo (#4338CA) background with white text and 12px rounding. Secondary buttons use a subtle gray border (#E2E8F0) with no fill.
- **Input Fields:** Default states feature a 1px border (#E2E8F0) and a white background. Focus states transition the border to Deep Indigo with a soft 2px outer glow in the same hue at 10% opacity.
- **Cards:** White backgrounds with 1px borders and 12px corner radii. No shadows are used for standard dashboard cards; they rely on the #F8FAFC page background for contrast.
- **Chips/Tags:** Used for status indicators (e.g., "High Risk," "Resolved"). These should have a light tinted background and matching border to keep them integrated but noticeable.
- **Data Tables:** Highly minimalist with no vertical borders. Row hover states use a subtle #F8FAFC tint to provide feedback without cluttering the view.
- **Security Specifics:** Status signals (Trust/Health) should utilize the Deep Indigo accent to signify "Safe," moving away from the common green to create a more unique brand signature.