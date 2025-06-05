<template>
  <div class="flex items-center">
    <div
      class="h-2.5 w-2.5 rounded-full mr-1.5"
      :class="{
        'bg-green-500': isOnline,
        'bg-yellow-500': isTyping,
        'bg-gray-300': !isOnline && !isTyping
      }"
    ></div>
    <span class="text-xs text-gray-500">{{ statusText }}</span>
  </div>
</template>

<script>
import { computed } from 'vue';
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
      default: null
    }
  },
  setup(props) {
    const isOnline = computed(() => {
      return WebSocketService.isUserOnline(props.userId);
    });

    const isTyping = computed(() => {
      if (!props.sessionId) return false;
      return WebSocketService.isUserTyping(props.sessionId);
    });

    const statusText = computed(() => {
      if (isTyping.value) return 'Escribiendo...';
      if (isOnline.value) return 'En línea';
      return 'Desconectado';
    });

    return {
      isOnline,
      isTyping,
      statusText
    };
  }
};
</script>
