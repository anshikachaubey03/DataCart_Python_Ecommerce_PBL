/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        // Mandatory Design Tokens
        cloud: "#ffffff",
        softCloud: "#f7f9fc",
        softGrey: "#e5eaf0",
        darkSlate: "#273247",
        mutedSlate: "#697586",

        // Sweet Coral Primary Accent (#FF795D)
        coral: {
          50: "#fff5f2",
          100: "#ffe8e2",
          200: "#ffd2c7",
          300: "#ffb4a2",
          400: "#ff9179",
          500: "#ff795d", // Primary Sweet Coral
          600: "#f05e3f",
          700: "#cc4629",
          800: "#a8371d",
          900: "#872f1a",
        },
        brand: {
          50: "#fff5f2",
          100: "#ffe8e2",
          200: "#ffd2c7",
          300: "#ffb4a2",
          400: "#ff9179",
          500: "#ff795d", // Maps brand to Sweet Coral
          600: "#f05e3f",
          700: "#cc4629",
          800: "#a8371d",
          900: "#872f1a",
          950: "#273247",
        },

        // Fresh Mint Supporting Pastel (#BFEDE0)
        mint: {
          50: "#f2fbf8",
          100: "#ebf9f5",
          200: "#d3f4ec",
          300: "#bfede0", // Fresh Mint
          400: "#80dcbe",
          500: "#3cc49d",
          600: "#1da37d",
          700: "#135e4b", // Accessible dark-green text
          800: "#114c3e",
          900: "#0e3f34",
        },

        // Sky Blue Supporting Pastel (#CFE5FF)
        sky: {
          50: "#f4f8fe",
          100: "#edf5ff",
          200: "#dfeeff",
          300: "#cfe5ff", // Sky Blue
          400: "#9ecaff",
          500: "#60a5fa",
          600: "#2563eb",
          700: "#1d4ed8", // Accessible dark-blue text
          800: "#1e40af",
          900: "#1e3a8a",
        },

        // Soft Lavender Supporting Pastel (#E9E1FF)
        lavender: {
          50: "#faf8ff",
          100: "#f5f0ff",
          200: "#efe8ff",
          300: "#e9e1ff", // Soft Lavender
          400: "#cfbfff",
          500: "#a78bfa",
          600: "#7c3aed",
          700: "#6d28d9", // Accessible dark-purple text
          800: "#5b21b6",
          900: "#4c1d95",
        },

        // Slates calibrated to Dark Slate (#273247) and Muted Slate (#697586)
        slate: {
          50: "#f7f9fc",  // Soft Cloud
          100: "#f1f5f9",
          200: "#e5eaf0", // Soft Grey
          300: "#cbd5e1",
          400: "#94a3b8",
          500: "#697586", // Muted Slate
          600: "#475569",
          700: "#334155",
          800: "#273247", // Dark Slate
          850: "#273247",
          900: "#273247", // Dark Slate primary text
          950: "#1a2232",
        },

        // Soft Warning & Error Pastels
        peach: {
          50: "#fff9f6",
          100: "#ffe4d6", // Soft Peach
          800: "#9a3412", // Accessible dark-orange text
        },
        softPink: {
          50: "#fef6f7",
          100: "#fde2e4", // Soft Pink
          800: "#9f1239", // Accessible dark-red text
        }
      },
      borderRadius: {
        'xl': '0.75rem',
        '2xl': '1rem',
        '3xl': '1.5rem',
      },
      boxShadow: {
        'soft': '0 2px 10px -2px rgba(39, 50, 71, 0.05), 0 1px 4px -1px rgba(39, 50, 71, 0.03)',
        'soft-md': '0 8px 24px -4px rgba(39, 50, 71, 0.08), 0 2px 6px -1px rgba(39, 50, 71, 0.04)',
        'soft-lg': '0 16px 36px -6px rgba(39, 50, 71, 0.1), 0 4px 12px -2px rgba(39, 50, 71, 0.05)',
        'coral': '0 8px 20px -4px rgba(255, 121, 93, 0.35)',
      }
    },
  },
  plugins: [],
};
