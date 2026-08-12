# Brand assets

The Skopos mark is a sonar scope: concentric range rings, a sweep, and a
single contact — σκοπός, the watcher, seeing something approach.

## Files

| File | Use |
| --- | --- |
| `skopos-icon.svg` | The full mark. Source of truth for anything ≥ 48 px. |
| `skopos-icon-small.svg` | Simplified variant for ≤ 32 px: no sweep, one less ring, thicker strokes, larger contact. The full mark collapses into a dark blob at tab size — this one stays readable. |
| `icon-1024.png`, `icon-512.png`, `icon-180.png`, `icon-32.png` | Rasterized full mark. `icon-512` is the one to upload as a Docker Hub / GitHub avatar. |
| `small-32.png` | Rasterized small variant, shipped as the dashboard favicon. |

The dashboard copies live in `web/public/` (`favicon.svg`, `favicon-32.png`,
`apple-touch-icon.png`, `icon-512.png`) so Vite serves them from the site root.

## Colours

| Token | Hex | Where |
| --- | --- | --- |
| Sonar teal | `#4cbcae` | Rings, accent. The brand colour. |
| Teal light | `#6fd2c5` / `#8ce9db` | Sweep leading edge, the contact. |
| Ground | `#0c1211` → `#16211f` | Icon tile, dashboard background (dark). |

The dashboard's full token set lives in `web/src/index.css`.

## Regenerating the PNGs

The SVGs are the source; the PNGs are rendered from them with headless
Chromium. Any SVG rasterizer works — `rsvg-convert`, Inkscape, or a browser:

```sh
rsvg-convert -w 512 -h 512 skopos-icon.svg -o icon-512.png
rsvg-convert -w 32  -h 32  skopos-icon-small.svg -o small-32.png
```

Keep the sizes that exist; other sizes are derived on demand.
