/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./static/landing.html"],
  theme: {
    extend: {
      fontFamily: {
        sans: ['"IBM Plex Sans"', 'system-ui', 'sans-serif'],
        display: ['"IBM Plex Sans"', 'system-ui', 'sans-serif'],
        mono: ['"IBM Plex Mono"', 'monospace'],
      },
      colors: {
        canvas: '#ECE7DD',      // warm paper canvas
        panel: '#FFFFFF',       // panel surface
        edge: '#DAD3C3',        // panel border edge
        sidebar: '#1B1F2B',     // charcoal-navy sidebar & header
        sidebarLine: '#2B3040', // sidebar divider
        ink: '#22262E',         // deep ink text
        inkMuted: '#6B6F7A',    // secondary muted ink
        inkSoft: '#8F93A0',     // soft caption text
        risk: {
          high: '#C1443B',      // risk/block red
          highBg: 'rgba(193, 68, 59, 0.10)',
          med: '#C98A2E',       // escalate amber
          medBg: 'rgba(201, 138, 46, 0.10)',
          low: '#4C7A5E',       // approve green
          lowBg: 'rgba(76, 122, 94, 0.10)',
        },
        activeBlue: '#3D5A80',  // active/link blue
        activeBlueBg: 'rgba(61, 90, 128, 0.10)',
      }
    }
  },
  plugins: []
};
