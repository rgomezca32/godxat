<template>
  <div id="app">
    <router-view></router-view>  <!-- Esto renderiza la vista según la ruta configurada -->
  </div>
</template>

<script>
export default {
  name: 'App',
};
</script>

<style>
/* Estilos globales para la aplicación */
#app {
  font-family: Avenir, Helvetica, Arial, sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  text-align: center;
  color: #2c3e50;
  margin-top: 60px;
}
</style>
