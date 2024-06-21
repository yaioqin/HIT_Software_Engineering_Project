const { defineConfig } = require('@vue/cli-service')
module.exports = defineConfig({
  devServer: {
    proxy: {
      '/api': {
        //target: 'http://192.168.1.103:9000', // 你的后端接口地址
        target: 'http://127.0.0.1:5000', // 你的后端接口地址
        changeOrigin: true,
        pathRewrite: {
          '^/api': ''
        }
      }
    }
  },
  transpileDependencies: true
})