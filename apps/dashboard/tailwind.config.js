/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        brand: '#FF6B35',
        safe: '#30D158',
        suspicious: '#FFD60A',
        dangerous: '#FF9500',
        critical: '#FF2D55',
      },
    },
  },
  plugins: [],
}
