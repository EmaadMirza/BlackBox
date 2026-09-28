# Design Reference

## Palette
- `--bg: #0A0A0B` (page)
- `--surface: #131316` (cards)
- `--surface-2: #1A1A1E` (accordion bars)
- `--border: #26262C` (used sparingly)
- `--red: #E4002B` (bright accent)
- `--crimson: #7A0C1A` (deep red)
- `--white: #F5F5F6`
- `--grey-100: #E2E2E5`
- `--grey-400: #9A9AA0`
- `--text-2: #A1A1AA`

Glow used on hero cards: `radial-gradient(ellipse at 85% 40%, rgba(122,12,26,.75) 0%, rgba(74,14,24,.45) 35%, transparent 70%)` over `--surface`.

NO green, blue or yellow anywhere. Status is shown through shape + icon + label, never colour alone:
- VERIFIED = white filled shield with check
- TAMPERED = solid red badge with cross
- MISSING = red dashed outline with gap icon
- UNVERIFIED = grey hollow badge with clock icon

## Typography
- A bold geometric sans (Plus Jakarta Sans -> Outfit -> Inter).
- Headlines weight 700-800, letter-spacing -0.02em, line-height 1.1, white, with ONE keyword or number in `--red` and a short red underline bar (48px x 2px) under hero titles.
- Body weight 300-400, large (18-20px on mobile), colour `--text-2` or `--white`.
- Subtitle text is small and grey.
- JetBrains Mono for hashes, IDs and code.
- Bundle all fonts locally (no CDN).

## Components
- Cards: rounded 8-12px, flat `--surface`, soft shadow, NO heavy borders. Hero cards use the radial crimson glow coming from the right, with a tiny credit line in the bottom-right corner ("BlackBox · ASYNC'26", 12px, grey).
- Swatch-card motif (signature element): a rounded rectangle split into horizontal colour bands (off-white, light grey, mid grey, bright red, deep crimson, near-black). Use three side by side with the middle one raised.
- Accordion bars: full-width, `--surface-2`, large text, a chevron on the right that rotates when open. Use them for "Table of Contents", "What am I looking at?", and the glossary.
- Meta rows: three light rows under the hero (e.g. Date published, Component, Read time).
- AI Summary section: heading followed by a plain-language summary card.

## Layout & Motion
- Mobile-first, one comfortable column with generous vertical spacing (48-80px).
- Desktop: max-width 1200px with multi-column grids inside cards. Sidebar navigation.
- Motion: 150-250ms transitions, subtle red glow on active elements, respect prefers-reduced-motion.
