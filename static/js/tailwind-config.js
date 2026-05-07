window.tailwind = window.tailwind || {};
window.tailwind.config = {
  darkMode: ['class', '[data-theme="dark"]'],
  theme: {
    extend: {
      fontFamily: {
        display: ['Oxanium', 'sans-serif'],
        sans: ['Space Mono', '-apple-system', 'BlinkMacSystemFont', 'sans-serif'],
        mono: ['Source Code Pro', 'monospace']
      }
    }
  }
};
