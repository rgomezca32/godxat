<template>
  <div class="user-status">
    <!-- Indicador de estado en línea -->
    <div class="flex items-center">
      <span
        v-if="isOnline"
        class="h-2.5 w-2.5 rounded-full bg-green-500 mr-1"
        title="En línea"
      ></span>
      <span
        v-else
        class="h-2.5 w-2.5 rounded-full bg-gray-300 mr-1"
        title="Desconectado"
      ></span>

      <!-- Indicador de escritura -->
      <span
        v-if="isTyping"
        class="text-xs text-blue-500 animate-pulse"
        title="Escribiendo..."
      >
        escribiendo...
      </span>
    </div>
  </div>
</template>

<script>
import { ref, onMounted, onBeforeUnmount, watch } from 'vue';
import WebSocketService from '@/services/websocket_service';

export default {
  name: 'UserStatus',
  props: {
    userId: {
      type: Number,
      required: true
    },
    sessionId: {
      type: String,
      required: true
    }
  },
  setup(props) {
    const isOnline = ref(false);
    const isTyping = ref(false);
    const typingTimeout = ref(null);

    // Verificar estado inicial
    onMounted(() => {
      updateOnlineStatus();
      updateTypingStatus();

      // Configurar intervalo para actualizar estado
      const statusInterval = setInterval(() => {
        updateOnlineStatus();
        updateTypingStatus();
      }, 5000);

      // Limpiar intervalo al desmontar
      onBeforeUnmount(() => {
        clearInterval(statusInterval);
        if (typingTimeout.value) {
          clearTimeout(typingTimeout.value);
        }
      });
    });

    // Observar cambios en las propiedades
    watch(() => props.userId, () => {
      updateOnlineStatus();
    });

    watch(() => props.sessionId, () => {
      updateTypingStatus();
    });

    // Función para actualizar estado en línea
    const updateOnlineStatus = () => {
      if (props.userId) {
        isOnline.value = WebSocketService.isUserOnline(props.userId);
      } else {
        isOnline.value = false;
      }
    };

    // Función para actualizar estado de escritura
    const updateTypingStatus = () => {
      if (props.sessionId) {
        isTyping.value = WebSocketService.isUserTyping(props.sessionId);

        // Si está escribiendo, configurar timeout para verificar de nuevo
        if (isTyping.value) {
          if (typingTimeout.value) {
            clearTimeout(typingTimeout.value);
          }

          typingTimeout.value = setTimeout(() => {
            updateTypingStatus();
          }, 3000);
        }
      } else {
        isTyping.value = false;
      }
    };

    return {
      isOnline,
      isTyping
    };
  }
};
</script>

<style scoped>
.user-status {
  display: inline-flex;
  align-items: center;
}
</style>
