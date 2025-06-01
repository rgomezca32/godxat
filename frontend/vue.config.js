// vue.config.js
module.exports = {
  // Evita que los archivos se sirvan desde rutas absolutas en producción
  publicPath: './',
  
  // Configuración para desarrollo
  devServer: {
    port: 8080
  },
  
  // Configuración de transpilación
  transpileDependencies: true,
  
  // Configuración de construcción
  configureWebpack: {
    // Optimizaciones para Tauri
    optimization: {
      splitChunks: {
        chunks: 'all'
      }
    }
  }
}