<template>
  <div class="flex items-center justify-center min-h-screen bg-gray-100">
    <div class="w-full max-w-md p-8 bg-white rounded-lg shadow-md">
      <!-- Logo o título -->
      <div class="text-center mb-8">
        <h1 class="text-2xl font-bold text-gray-800">GodXat</h1>
        <p class="text-gray-600 mt-2">Inicia sesión para continuar</p>
      </div>

      <!-- Formulario de login -->
      <form @submit.prevent="login" class="space-y-6">
        <!-- Campo de usuario -->
        <div class="space-y-2">
          <div class="flex items-center justify-between">
            <label for="username" class="block text-sm font-medium text-gray-700">
              Usuario
            </label>
          </div>
          <input
            id="username"
            v-model="username"
            type="text"
            required
            class="w-full px-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            placeholder="Ingresa tu nombre de usuario"
          />
        </div>

        <!-- Campo de contraseña -->
        <div class="space-y-2">
          <div class="flex items-center justify-between">
            <label for="password" class="block text-sm font-medium text-gray-700">
              Contraseña
            </label>
          </div>
          <input
            id="password"
            v-model="password"
            type="password"
            required
            class="w-full px-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            placeholder="Ingresa tu contraseña"
          />
        </div>

        <!-- Recordarme -->
        <div class="flex items-center">
          <input
            id="remember-me"
            type="checkbox"
            v-model="rememberMe"
            class="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
          />
          <label for="remember-me" class="ml-2 block text-sm text-gray-700">
            Recordarme
          </label>
        </div>

        <!-- Botón de inicio de sesión -->
        <button
          type="submit"
          class="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-500 hover:bg-blue-600 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
        >
          Iniciar sesión
        </button>
      </form>

      <!-- Separador -->
      <div class="relative my-6">
        <div class="absolute inset-0 flex items-center">
          <div class="w-full border-t border-gray-300"></div>
        </div>
        <div class="relative flex justify-center text-sm">
          <span class="px-2 bg-white text-gray-500">O</span>
        </div>
      </div>

      <!-- Enlace para registrarse -->
      <div class="text-center mt-6">
        <p class="text-sm text-gray-600">
          ¿No tienes una cuenta?
          <router-link to="/register" class="font-medium text-blue-600 hover:underline">
            Regístrate
          </router-link>
        </p>
      </div>
    </div>
  </div>
</template>

<script setup>
import { useRouter } from 'vue-router'
import { ref } from 'vue';
import axios from '@/axios';
import { onMounted } from 'vue'
const router = useRouter()
// Estado del formulario
const username = ref('');
const password = ref('');
const rememberMe = ref(false);

onMounted(() => {
  if (localStorage.getItem('access_token')) {
    router.push('/message')
  }
})

// Función de inicio de sesión
const login = async () => {
  try {
    const response = await axios.post('/login/', {
      username: username.value,
      password: password.value
    })
    localStorage.setItem('access_token', response.data.access_token)
    router.push('/message')
  } catch (error) {
    // Verifica si existe error.response y error.response.data.detail
    const message = error.response?.data?.detail || error.message || 'Error desconocido'
    console.error('Error al iniciar sesión:', message)
    alert(message)
  }
}
</script>

<style scoped>
</style>
