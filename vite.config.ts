import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// GitHub Pages ではリポジトリ名がパスに入るため、CI からのみ base を差し替える
const base = process.env.MITORI_BASE ?? '/'

export default defineConfig({
  base,
  plugins: [react(), tailwindcss()],
})
