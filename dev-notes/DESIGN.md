---
name: ConfigGuard
colors:
  surface: '#0b1326'
  surface-dim: '#0b1326'
  surface-bright: '#31394d'
  surface-container-lowest: '#060e20'
  surface-container-low: '#131b2e'
  surface-container: '#171f33'
  surface-container-high: '#222a3d'
  surface-container-highest: '#2d3449'
  on-surface: '#dae2fd'
  on-surface-variant: '#bcc9c6'
  inverse-surface: '#dae2fd'
  inverse-on-surface: '#283044'
  outline: '#879391'
  outline-variant: '#3d4947'
  surface-tint: '#6bd8cb'
  primary: '#6bd8cb'
  on-primary: '#003732'
  primary-container: '#29a195'
  on-primary-container: '#00302b'
  inverse-primary: '#006a61'
  secondary: '#93ccff'
  on-secondary: '#003351'
  secondary-container: '#3198dc'
  on-secondary-container: '#002c47'
  tertiary: '#4edea3'
  on-tertiary: '#003824'
  tertiary-container: '#00a572'
  on-tertiary-container: '#00311f'
  error: '#ffb4ab'
  on-error: '#690005'
  error-container: '#93000a'
  on-error-container: '#ffdad6'
  primary-fixed: '#89f5e7'
  primary-fixed-dim: '#6bd8cb'
  on-primary-fixed: '#00201d'
  on-primary-fixed-variant: '#005049'
  secondary-fixed: '#cce5ff'
  secondary-fixed-dim: '#93ccff'
  on-secondary-fixed: '#001d31'
  on-secondary-fixed-variant: '#004b73'
  tertiary-fixed: '#6ffbbe'
  tertiary-fixed-dim: '#4edea3'
  on-tertiary-fixed: '#002113'
  on-tertiary-fixed-variant: '#005236'
  background: '#0b1326'
  on-background: '#dae2fd'
  surface-variant: '#2d3449'
typography:
  display-lg:
    fontFamily: Inter
    fontSize: 48px
    fontWeight: '700'
    lineHeight: 56px
    letterSpacing: -0.02em
  headline-lg:
    fontFamily: Inter
    fontSize: 32px
    fontWeight: '600'
    lineHeight: 40px
    letterSpacing: -0.01em
  headline-lg-mobile:
    fontFamily: Inter
    fontSize: 24px
    fontWeight: '600'
    lineHeight: 32px
  title-md:
    fontFamily: Inter
    fontSize: 20px
    fontWeight: '600'
    lineHeight: 28px
  body-md:
    fontFamily: Inter
    fontSize: 16px
    fontWeight: '400'
    lineHeight: 24px
  body-sm:
    fontFamily: Inter
    fontSize: 14px
    fontWeight: '400'
    lineHeight: 20px
  code-md:
    fontFamily: JetBrains Mono
    fontSize: 14px
    fontWeight: '400'
    lineHeight: 22px
  label-caps:
    fontFamily: Inter
    fontSize: 12px
    fontWeight: '700'
    lineHeight: 16px
    letterSpacing: 0.05em
rounded:
  sm: 0.25rem
  DEFAULT: 0.5rem
  md: 0.75rem
  lg: 1rem
  xl: 1.5rem
  full: 9999px
spacing:
  base: 4px
  xs: 4px
  sm: 8px
  md: 16px
  lg: 24px
  xl: 32px
  gutter: 24px
  margin-mobile: 16px
  margin-desktop: 48px
---

## Brand & Style
The design system is engineered for a high-stakes security environment where precision and clarity are paramount. The brand personality is authoritative yet approachable, prioritizing information density without sacrificing legibility. 

The aesthetic follows a **Modern Corporate** style with leanings toward **Minimalism** and **Technical Precision**. It utilizes a sophisticated dark-mode-first approach to reduce eye strain during long periods of technical auditing. Visual interest is generated through vibrant, functional accents rather than decorative elements. Every UI component is designed to feel "locked-in" and stable, reflecting the security and reliability of the underlying infrastructure.

## Colors
The palette is rooted in a deep navy and charcoal foundation (`#0f172a`), providing a high-contrast environment for technical data.

- **Primary & Secondary:** Teal (`#0d9488`) and Electric Blue (`#0284c7`) are used for interactive states, primary actions, and brand highlights. 
- **Severity System:** A strict semantic color system is employed for risk assessment. These colors must maintain a high luminance contrast against the dark backgrounds to ensure accessibility.
- **Surface Tiers:** Use subtle variations of the neutral base (e.g., `#1e293b`) to differentiate between background, container, and elevated surfaces.

## Typography
The typography system balances human-readable UI elements with machine-readable data.

- **UI Sans:** `Inter` is the workhorse for the interface, chosen for its excellent legibility at small sizes and neutral tone.
- **Technical Mono:** `JetBrains Mono` is reserved for configuration files, CLI commands, and raw data outputs. It should always be used in a container with a slightly darker background to distinguish "data" from "interface."
- **Scale:** Use tight tracking on larger headlines to maintain a modern, "compacted" feel.

## Layout & Spacing
The design system utilizes a **12-column fluid grid** for desktop and a **4-column grid** for mobile. 

- **Spacing Rhythm:** Based on a 4px baseline, but defaults to 8px increments for most component spacing.
- **Data Density:** In complex dashboards, utilize a "compact" spacing mode (8px padding in lists/tables) to maximize visible information. Standard pages should use 16px or 24px margins for better breathability.
- **Grid Behavior:** Margins are fixed at 48px on desktop to provide a professional frame, while the inner columns flex to fill the space.

## Elevation & Depth
Depth is conveyed through **Tonal Layering** and **Subtle Outlines** rather than aggressive shadows. 

- **Surface Levels:** The base background is the darkest. Cards and modals use a slightly lighter shade of charcoal.
- **Borders:** All containers must have a 1px solid border (`#ffffff10` or a tinted equivalent) to define edges against the dark background.
- **Shadows:** Use extra-diffused "Ambient Shadows." Shadows should be large in radius but very low in opacity (5-10%), acting as a subtle "glow" or lift rather than a traditional drop shadow.

## Shapes
The shape language is structured and "Soft-Industrial." 

- **Standard Radius:** 12px (0.75rem) for cards and main containers.
- **Component Radius:** 6px to 8px for smaller elements like buttons and input fields to give them a sharper, more precise feel compared to the layout containers.
- **Status Indicators:** Status pips and active indicators use 100% rounding (pills) to distinguish them from structural UI.

## Components
- **Buttons:** Primary buttons use a solid teal gradient (`#0d9488` to `#0f766e`). Secondary buttons are "Ghost" style with a 1px electric blue border.
- **Cards:** Cards are the primary layout unit. They feature a 12px corner radius, a subtle 1px border, and a soft ambient shadow. 
- **Status Badges:** Use a "soft-fill" approach (10% opacity background of the severity color with 100% opacity text) for better legibility on dark backgrounds.
- **Input Fields:** Use a dark, recessed background with a 1px border that glows Electric Blue on focus.
- **Progress Rings:** Use stroke-based circular indicators. The stroke weight should be thin (2px - 4px) to remain consistent with the iconography.
- **Icons:** 24px grid, 1.5pt stroke weight. Avoid filled icons unless indicating an active/toggled state.
- **Configuration Blocks:** Always monospaced, inside a rounded container with a "Copy to Clipboard" persistent action in the top right corner.