/** @type {import('tailwindcss').Config} */
export default {
  content: ["./src/renderer/index.html", "./src/renderer/src/**/*.{ts,tsx}"],
  darkMode: ["class", '[data-theme="dark"]'],
  theme: {
    extend: {
      fontFamily: {
        sans: [
          "Inter",
          "Inter Variable",
          "-apple-system",
          "BlinkMacSystemFont",
          "Segoe UI",
          "sans-serif",
        ],
        mono: [
          "Geist Mono",
          "JetBrains Mono",
          "ui-monospace",
          "SFMono-Regular",
          "Menlo",
          "monospace",
        ],
        // Wordmark — Tesla typeface (locally bundled, CC-BY-SA 4.0).
        // Tesla's E renders as three free-floating horizontal bars by design.
        display: [
          "Tesla",
          "Iceland",
          "Inter",
          "sans-serif",
        ],
      },
      colors: {
        // Surface ramp — dark-first, oklch deep-but-not-pure-black
        surface: {
          0: "var(--color-surface-0)",
          1: "var(--color-surface-1)",
          2: "var(--color-surface-2)",
          3: "var(--color-surface-3)",
        },
        ink: {
          DEFAULT: "var(--color-ink)",
          body: "var(--color-ink-body)",
          muted: "var(--color-ink-muted)",
        },
        line: "var(--color-line)",
        // Tesla electric cyan — desaturated for dark surfaces
        accent: {
          DEFAULT: "var(--color-accent)",
          hover: "var(--color-accent-hover)",
          tint: "var(--color-accent-tint)",
        },
        threat: {
          allow: "var(--color-threat-allow)",
          warn: "var(--color-threat-warn)",
          block: "var(--color-threat-block)",
        },
      },
      borderRadius: {
        xs: "var(--radius-xs)",
        sm: "var(--radius-sm)",
        DEFAULT: "var(--radius-md)",
        md: "var(--radius-md)",
        lg: "var(--radius-lg)",
        xl: "var(--radius-xl)",
      },
      transitionTimingFunction: {
        "tesla": "cubic-bezier(0.16, 1, 0.3, 1)",
      },
      transitionDuration: {
        "fast": "120ms",
        "base": "200ms",
        "slow": "400ms",
      },
    },
  },
  plugins: [],
};
