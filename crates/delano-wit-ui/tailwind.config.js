/** @type {import('tailwindcss').Config} */
module.exports = {
  content: {
    files: ["./src/templates/*.html"],
  },
  theme: {
    extend: {
      keyframes: {
        wiggle: {
          "0%, 100%": { transform: "rotate(-3deg)" },
          "50%": { transform: "rotate(3deg)" },
        },
        // Slide: y-axis down when entering and up when exiting
        slideDown: {
          "0%": { transform: "translateY(-100%)" },
          "100%": { transform: "translateY(0)" },
        },
      },
      animation: {
        wiggle: "wiggle 1s ease-in-out infinite",
        slideDown: "slideDown 0.3s ease-in-out",
      },
    },
  },
  plugins: [],
};
