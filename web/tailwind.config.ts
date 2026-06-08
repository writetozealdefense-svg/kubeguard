import type { Config } from "tailwindcss";

// KubeGuard design tokens — dark theme + severity palette (CRITICAL→INFO).
export default {
  darkMode: "class",
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        bg: { DEFAULT: "#0b0e14", surface: "#11161f", raised: "#161d29" },
        border: { DEFAULT: "#1f2937", strong: "#374151" },
        fg: { DEFAULT: "#e5e7eb", muted: "#9ca3af", subtle: "#6b7280" },
        accent: { DEFAULT: "#3b82f6", fg: "#ffffff" },
        // Severity palette — used by cards, badges, charts, graph nodes.
        sev: {
          critical: "#dc2626",
          high: "#ea580c",
          medium: "#d97706",
          low: "#2563eb",
          info: "#6b7280",
        },
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "monospace"],
      },
    },
  },
  plugins: [],
} satisfies Config;
