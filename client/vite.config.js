import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  server: {
    host: '127.0.0.1',
    proxy: Object.fromEntries(['/api', '/login', '/register', '/logout', '/verify', '/account', '/admin', '/static'].map(path => [path, 'http://127.0.0.1:5001'])),
  },
  plugins: [
    react(),
    tailwindcss(),
  ],
});
