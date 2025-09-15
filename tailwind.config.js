/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./templates/**/*.{html,js}"],
  theme: {
    extend: {
      colors: {
        primary: '#3b82f6',    // 已存在：对应 text-primary、bg-primary 等
        secondary: '#6b7280',  // 已存在：对应 text-secondary 等
        dark: '#1f2937',       // 已存在：对应 text-dark 等
        warning: '#f59e0b',    // 已存在：对应 text-warning 等
        // 需要新增的颜色配置
        danger: '#ef4444',     // 对应 host.html 中的 text-danger、bg-danger
        success: '#10b981',    // 对应提示消息中的 bg-success
      },
    },
  },
  plugins: [],
}