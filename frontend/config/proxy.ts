// 开发环境只连接本项目后端；生产环境由同源反向代理转发 /api。
export default {
  dev: {
    '/api/': {
      // VS Code/.NET 默认使用本地 HTTPS 5001；如改用其他后端地址，请设置 SSL_API_PROXY。
      target: process.env.SSL_API_PROXY || 'https://localhost:5001',
      changeOrigin: true,
      // 仅开发代理允许本机开发证书，不影响生产 HTTPS 校验。
      secure: false,
    },
  },
};
