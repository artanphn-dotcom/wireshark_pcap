import type { Config } from "tailwindcss";

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        canvas: "var(--bg)",
        ink: "var(--text)",
        panel: "var(--card)",
        edge: "var(--border)",
        accent: "var(--accent)",
        accent2: "var(--accent2)",
        ok: "var(--ok)",
        bad: "var(--bad)",
        warn: "var(--warn)",
      },
      fontFamily: {
        display: ["'Space Grotesk'", "sans-serif"],
        mono: ["'IBM Plex Mono'", "monospace"],
      },
      boxShadow: {
        panel: "0 10px 30px rgba(7, 37, 38, 0.10)",
      },
      keyframes: {
        rise: {
          "0%": { opacity: "0", transform: "translateY(12px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
      },
      animation: {
        rise: "rise 480ms ease-out both",
      },
    },
  },
  plugins: [],
} satisfies Config;
