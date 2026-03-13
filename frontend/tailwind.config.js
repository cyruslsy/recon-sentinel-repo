/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./src/**/*.{js,ts,jsx,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        sentinel: {
          bg: "#0B0E14",
          surface: "#111720",
          card: "#161D2A",
          border: "#1E2A3A",
          hover: "#1A2435",
          text: "#E2E8F0",
          muted: "#64748B",
          accent: "#3B82F6",
          green: "#22C55E",
          red: "#EF4444",
          orange: "#F59E0B",
          purple: "#A78BFA",
        },
      },
      fontFamily: {
        mono: ["JetBrains Mono", "Fira Code", "monospace"],
      },
    },
  },
  plugins: [],
};
