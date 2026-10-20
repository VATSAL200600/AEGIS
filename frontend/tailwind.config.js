/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        "surface": "#f7f9fb",
        "surface-bright": "#f7f9fb",
        "surface-dim": "#d8dadc",
        "surface-container-lowest": "#ffffff",
        "surface-container-low": "#f2f4f6",
        "surface-container": "#eceef0",
        "surface-container-high": "#e6e8ea",
        "surface-container-highest": "#e0e3e5",
        "surface-variant": "#e0e3e5",
        "surface-tint": "#2151da",
        "background": "#f7f9fb",
        "on-background": "#191c1e",
        "on-surface": "#191c1e",
        "on-surface-variant": "#434655",
        "outline": "#747686",
        "outline-variant": "#c4c5d7",
        
        "primary": "#0037b0",
        "primary-container": "#1d4ed8",
        "on-primary": "#ffffff",
        "on-primary-container": "#cad3ff",
        "primary-fixed": "#dce1ff",
        "primary-fixed-dim": "#b7c4ff",

        "secondary": "#565e74",
        "secondary-container": "#dae2fd",
        "on-secondary": "#ffffff",
        "on-secondary-container": "#5c647a",
        "on-secondary-fixed": "#131b2e",

        "tertiary": "#7f2500",
        "tertiary-container": "#a73400",
        "tertiary-fixed": "#ffdbcf",
        "on-tertiary-fixed": "#390c00",
        "on-tertiary-container": "#ffc9b7",

        "error": "#ba1a1a",
        "error-container": "#ffdad6",
        "on-error-container": "#93000a",
      },
      fontFamily: {
        headline: ["Geist", "Inter", "system-ui", "sans-serif"],
        body: ["Hanken Grotesk", "Inter", "system-ui", "sans-serif"],
        mono: ["GeistMono", "JetBrains Mono", "SF Mono", "monospace"],
      },
      spacing: {
        'margin': '1.5rem',
        'gutter': '1rem',
        'space-xxs': '0.125rem',
        'space-xs': '0.25rem',
        'space-sm': '0.5rem',
        'space-md': '0.75rem',
        'space-lg': '1rem',
        'space-xl': '1.5rem',
        'space-2xl': '2rem',
      }
    },
  },
  plugins: [],
}
