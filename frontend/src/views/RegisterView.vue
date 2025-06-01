<template>
  <div class="flex items-center justify-center min-h-screen bg-gray-100">
    <div class="w-full max-w-md p-8 bg-white rounded-lg shadow-md">
      <!-- Logo o título -->
      <div class="text-center mb-8">
        <h1 class="text-2xl font-bold text-gray-800">Crear cuenta</h1>
        <p class="text-gray-600 mt-2">Únete a nuestra comunidad</p>
      </div>

      <!-- Formulario de registro -->
      <form @submit.prevent="register" class="space-y-6">
        <!-- Campo de nombre de usuario -->
        <div class="space-y-2">
          <label for="username" class="block text-sm font-medium text-gray-700">
            Nombre de usuario
          </label>
          <input
            id="username"
            v-model="username"
            type="text"
            required
            class="w-full px-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            placeholder="Elige un nombre de usuario"
          />
        </div>

        <!-- Campo de contraseña -->
        <div class="space-y-2">
          <label for="password" class="block text-sm font-medium text-gray-700">
            Contraseña
          </label>
          <input
            id="password"
            v-model="password"
            type="password"
            required
            class="w-full px-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            placeholder="Mínimo 8 caracteres"
          />
          <!-- Indicador de fortaleza de contraseña -->
          <div class="mt-2">
            <div class="flex space-x-1">
              <div
                class="h-1 flex-1 rounded"
                :class="passwordStrength >= 1 ? 'bg-red-500' : 'bg-gray-200'"
              ></div>
              <div
                class="h-1 flex-1 rounded"
                :class="passwordStrength >= 2 ? 'bg-yellow-500' : 'bg-gray-200'"
              ></div>
              <div
                class="h-1 flex-1 rounded"
                :class="passwordStrength >= 3 ? 'bg-green-500' : 'bg-gray-200'"
              ></div>
            </div>
            <p class="text-xs text-gray-500 mt-1">
              {{ passwordStrengthText }}
            </p>
          </div>
        </div>

        <!-- Campo de confirmar contraseña -->
        <div class="space-y-2">
          <label for="confirmPassword" class="block text-sm font-medium text-gray-700">
            Confirmar contraseña
          </label>
          <input
            id="confirmPassword"
            v-model="confirmPassword"
            type="password"
            required
            class="w-full px-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            :class="{ 'border-red-500': confirmPassword && password !== confirmPassword }"
            placeholder="Repite tu contraseña"
          />
          <p v-if="confirmPassword && password !== confirmPassword" class="text-xs text-red-500">
            Las contraseñas no coinciden
          </p>
        </div>

        <!-- Términos y condiciones -->
        <div class="flex items-start">
          <input
            id="terms"
            type="checkbox"
            v-model="acceptTerms"
            required
            class="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded mt-1"
          />
          <label for="terms" class="ml-2 block text-sm text-gray-700">
            Acepto los
            <a href="#" class="text-blue-600 hover:underline">términos y condiciones</a>
            y la
            <a href="#" class="text-blue-600 hover:underline">política de privacidad</a>
          </label>
        </div>

        <!-- Botón de registro -->
        <button
          type="submit"
          :disabled="!isFormValid"
          class="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-500 hover:bg-blue-600 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          Crear cuenta
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

      <!-- Enlace para iniciar sesión -->
      <div class="text-center mt-6">
        <p class="text-sm text-gray-600">
          ¿Ya tienes una cuenta?
          <a href="/" class="font-medium text-blue-600 hover:underline">
            Inicia sesión
          </a>
        </p>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed } from 'vue';
import { useRouter } from 'vue-router';
const router = useRouter();
import axios from '@/axios';
// Estado del formulario
const username = ref('');
const password = ref('');
const confirmPassword = ref('');
const acceptTerms = ref(false);

// Computed para validar la fortaleza de la contraseña
const passwordStrength = computed(() => {
  if (!password.value) return 0;

  let strength = 0;

  // Longitud mínima
  if (password.value.length >= 8) strength++;

  // Contiene números y letras
  if (/(?=.*[a-zA-Z])(?=.*[0-9])/.test(password.value)) strength++;

  // Contiene caracteres especiales
  if (/(?=.*[!@#$%^&*])/.test(password.value)) strength++;

  return strength;
});

// Texto descriptivo de la fortaleza de la contraseña
const passwordStrengthText = computed(() => {
  switch (passwordStrength.value) {
    case 0:
      return 'Muy débil';
    case 1:
      return 'Débil';
    case 2:
      return 'Moderada';
    case 3:
      return 'Fuerte';
    default:
      return '';
  }
});

// Validación del formulario
const isFormValid = computed(() => {
  return (
    username.value.trim() !== '' &&
    password.value.length >= 8 &&
    password.value === confirmPassword.value &&
    acceptTerms.value
  );
});

// Función de registro
const register = async () => {
  if (!isFormValid.value) {
    alert('Por favor, completa todos los campos correctamente.');
    return;
  }

  try {
    const response = await axios.post('/register/', {
      username: username.value,
      password: password.value
    });

    console.log('Usuario registrado:', response.data);
    alert('Usuario registrado exitosamente. Redirigiendo...');

    setTimeout(() => {
      router.push("/");
    }, 1000);

  } catch (error) {
    if (error.response) {
      console.error('Error del servidor:', error.response.data.detail);
      alert(`Error: ${error.response.data.detail}`);
    } else {
      console.error('Error de red:', error.message);
      alert('No se pudo conectar con el servidor.');
    }
  }
};

</script>
