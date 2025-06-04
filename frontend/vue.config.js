const path = require('path');

module.exports = {
  publicPath: './',
  devServer: {
    port: 8080,
  },
  transpileDependencies: true,
  configureWebpack: {
    optimization: {
      splitChunks: {
        chunks: 'all',
      },
    },
    resolve: {
      alias: {
        '@tauri-apps/api': path.resolve(__dirname, 'node_modules/@tauri-apps/api'),
      },
    },
  },
};
