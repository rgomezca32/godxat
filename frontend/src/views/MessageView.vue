<template>
  <div class="flex h-screen bg-gray-100 overflow-hidden">
    <!-- Lista de usuarios y sesiones -->
    <div class="w-full md:w-1/3 bg-white border-r border-gray-200">
      <div class="p-4 border-b border-gray-200 flex justify-between items-center">
        <h1 class="text-xl font-bold">Mensajes</h1>
        <div class="flex items-center space-x-2">
          <!-- Botón para añadir amigos -->
          <div class="relative">
            <button
              @click="toggleAddFriendMenu"
              class="h-8 w-8 rounded-full bg-blue-500 text-white flex items-center justify-center hover:bg-blue-600 transition-colors"
              title="Añadir amigos"
            >
              <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <line x1="12" y1="5" x2="12" y2="19"></line>
                <line x1="5" y1="12" x2="19" y2="12"></line>
              </svg>
            </button>

            <!-- Menú desplegable para añadir amigos -->
            <div
              v-if="isAddFriendMenuOpen"
              class="absolute right-0 mt-2 w-64 bg-white rounded-md shadow-lg z-10 border border-gray-200"
            >
              <div class="p-3">
                <h3 class="text-sm font-medium mb-2">Añadir amigo</h3>
                <input
                  v-model="newFriendName"
                  type="text"
                  placeholder="Nombre de usuario o email"
                  class="w-full px-3 py-2 text-sm border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 mb-2"
                  @keyup.enter="addFriend"
                />
                <button
                  @click="addFriend"
                  class="w-full px-3 py-2 text-sm bg-blue-500 text-white rounded-md hover:bg-blue-600 transition-colors mb-2"
                >
                  Buscar
                </button>

                <!-- Lista de posibles amigos -->
                <ul v-if="potentialFriends.length > 0" class="max-h-48 overflow-auto">
                  <li
                    v-for="friend in potentialFriends"
                    :key="friend.id"
                    @click="selectFriendFromList(friend)"
                    class="flex items-center p-2 cursor-pointer hover:bg-blue-100 rounded"
                  >
                    <img
                      :src="friend.avatar || '/placeholder.svg?height=40&width=40'"
                      alt="avatar"
                      class="w-8 h-8 rounded-full mr-2"
                    />
                    <span>{{ friend.username }}</span>
                  </li>
                </ul>
              </div>
            </div>
          </div>

          <!-- Botón de perfil -->
          <div class="relative">
            <button
              @click="toggleProfileMenu"
              class="h-8 w-8 rounded-full bg-gray-200 flex items-center justify-center overflow-hidden hover:bg-gray-300 transition-colors"
              title="Mi perfil"
            >
              <img src="/placeholder.svg?height=32&width=32" alt="Mi perfil" class="h-full w-full object-cover" />
            </button>

            <!-- Menú desplegable de perfil -->
            <div
              v-if="isProfileMenuOpen"
              class="absolute right-0 mt-2 w-48 bg-white rounded-md shadow-lg z-10 border border-gray-200"
            >
              <div class="py-1">
                <button
                  @click="viewProfile"
                  class="block w-full text-left px-4 py-2 text-sm text-gray-700 hover:bg-gray-100"
                >
                  Ver perfil
                </button>
                <button
                  @click="logout"
                  class="block w-full text-left px-4 py-2 text-sm text-gray-700 hover:bg-gray-100"
                >
                  Cerrar sesión
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Sección de solicitudes pendientes recibidas -->
      <div v-if="incomingPendingSessions.length > 0" class="bg-yellow-50 border-b border-yellow-200">
        <div class="p-3">
          <h3 class="text-sm font-medium text-yellow-800 mb-2">Solicitudes pendientes de aceptar</h3>
          <div class="space-y-2 max-h-48 overflow-y-auto">
            <div
              v-for="session in incomingPendingSessions"
              :key="session.session_id"
              class="flex items-center justify-between bg-white p-2 rounded-md border border-yellow-200"
            >
              <div class="flex items-center">
                <div class="h-8 w-8 rounded-full bg-gray-200 flex items-center justify-center overflow-hidden mr-2">
                  <img
                    :src="`/placeholder.svg?height=32&width=32`"
                    :alt="session.initiator_username"
                    class="h-full w-full object-cover"
                  />
                </div>
                <div>
                  <p class="text-sm font-medium">{{ session.initiator_username }}</p>
                  <p class="text-xs text-gray-500">Solicita iniciar una sesión segura</p>
                </div>
              </div>
              <div class="flex space-x-2">
                <button
                  @click="acceptSession(session.session_id, session.initiator_id)"
                  class="p-1.5 bg-green-500 text-white rounded-full hover:bg-green-600 transition-colors"
                  title="Aceptar"
                >
                  <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" viewBox="0 0 20 20" fill="currentColor">
                    <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd" />
                  </svg>
                </button>
                <button
                  @click="rejectSession(session.session_id)"
                  class="p-1.5 bg-red-500 text-white rounded-full hover:bg-red-600 transition-colors"
                  title="Rechazar"
                >
                  <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" viewBox="0 0 20 20" fill="currentColor">
                    <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd" />
                  </svg>
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Sección de solicitudes pendientes enviadas -->
      <div v-if="outgoingPendingSessions.length > 0" class="bg-blue-50 border-b border-blue-200">
        <div class="p-3">
          <h3 class="text-sm font-medium text-blue-800 mb-2">Esperando aceptación</h3>
          <div class="space-y-2 max-h-48 overflow-y-auto">
            <div
              v-for="session in outgoingPendingSessions"
              :key="session.session_id"
              class="flex items-center justify-between bg-white p-2 rounded-md border border-blue-200"
            >
              <div class="flex items-center">
                <div class="h-8 w-8 rounded-full bg-gray-200 flex items-center justify-center overflow-hidden mr-2">
                  <img
                    :src="`/placeholder.svg?height=32&width=32`"
                    :alt="session.receiver_username"
                    class="h-full w-full object-cover"
                  />
                </div>
                <div>
                  <p class="text-sm font-medium">{{ session.receiver_username }}</p>
                  <p class="text-xs text-gray-500">Esperando que acepte tu solicitud</p>
                </div>
              </div>
              <div class="flex space-x-2">
                <button
                  @click="cancelSession(session.session_id)"
                  class="p-1.5 bg-gray-500 text-white rounded-full hover:bg-gray-600 transition-colors"
                  title="Cancelar"
                >
                  <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" viewBox="0 0 20 20" fill="currentColor">
                    <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd" />
                  </svg>
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Lista de conversaciones activas -->
      <div class="overflow-y-auto h-[calc(100vh-64px)]">
        <h3 class="text-sm font-medium text-gray-700 p-3 bg-gray-50 border-b border-gray-200">Conversaciones activas</h3>
        <div
          v-for="user in activeUsers"
          :key="user.id"
          class="p-4 border-b border-gray-100 hover:bg-gray-50 cursor-pointer"
          :class="{ 'bg-gray-100': selectedUser && selectedUser.id === user.id }"
          @click="selectUser(user)"
        >
          <div class="flex items-center space-x-3">
            <div class="h-10 w-10 rounded-full bg-gray-200 flex items-center justify-center overflow-hidden">
              <img :src="user.avatar" :alt="user.name" class="h-full w-full object-cover" />
            </div>
            <div class="flex-1 min-w-0">
              <div class="flex justify-between items-center">
                <h3 class="text-sm font-medium text-gray-900 truncate">{{ user.name }}</h3>
                <span class="text-xs text-gray-500">{{ user.lastMessageTime }}</span>
              </div>
              <p class="text-sm text-gray-500 truncate">{{ user.lastMessage }}</p>
            </div>
            <div v-if="user.unread > 0" class="bg-blue-500 text-white text-xs rounded-full px-2 py-1 min-w-[20px] text-center">
              {{ user.unread }}
            </div>
            <!-- Indicador de sesión segura -->
            <div class="text-green-500" title="Sesión segura activa">
              <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" viewBox="0 0 20 20" fill="currentColor">
                <path fill-rule="evenodd" d="M5 9V7a5 5 0 0110 0v2a2 2 0 012 2v5a2 2 0 01-2 2H5a2 2 0 01-2-2v-5a2 2 0 012-2zm8-2v2H7V7a3 3 0 016 0z" clip-rule="evenodd" />
              </svg>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Área de chat (escritorio) -->
    <div class="hidden md:flex md:flex-col md:w-2/3 bg-gray-50">
      <template v-if="selectedUser">
        <!-- Cabecera del chat -->
        <div class="flex items-center justify-between p-4 border-b border-gray-200 bg-white">
          <div class="flex items-center">
            <div class="h-10 w-10 rounded-full bg-gray-200 flex items-center justify-center overflow-hidden">
              <img :src="selectedUser.avatar" :alt="selectedUser.name" class="h-full w-full object-cover" />
            </div>
            <div class="ml-3">
              <h2 class="text-lg font-semibold">{{ selectedUser.name }}</h2>
              <!-- Indicador de estado de sesión -->
              <div v-if="selectedUser.sessionStatus === 'active'" class="flex items-center text-xs text-green-600">
                <svg xmlns="http://www.w3.org/2000/svg" class="h-3 w-3 mr-1" viewBox="0 0 20 20" fill="currentColor">
                  <path fill-rule="evenodd" d="M5 9V7a5 5 0 0110 0v2a2 2 0 012 2v5a2 2 0 01-2 2H5a2 2 0 01-2-2v-5a2 2 0 012-2zm8-2v2H7V7a3 3 0 016 0z" clip-rule="evenodd" />
                </svg>
                <span>Sesión segura activa</span>
              </div>
              <div v-else-if="selectedUser.sessionStatus === 'pending'" class="flex items-center text-xs text-yellow-600">
                <svg xmlns="http://www.w3.org/2000/svg" class="h-3 w-3 mr-1" viewBox="0 0 20 20" fill="currentColor">
                  <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm1-12a1 1 0 10-2 0v4a1 1 0 00.293.707l2.828 2.829a1 1 0 101.415-1.415L11 9.586V6z" clip-rule="evenodd" />
                </svg>
                <span>Sesión pendiente</span>
              </div>
            </div>
          </div>
          <div class="flex items-center">
            <!-- Botón para eliminar sesión y mensajes -->
            <button
              v-if="selectedUser.sessionStatus === 'active'"
              @click="confirmDeleteSession"
              class="p-2 rounded-full hover:bg-red-100 transition-colors text-red-500 mr-2"
              title="Eliminar conversación"
            >
              <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
                <path fill-rule="evenodd" d="M9 2a1 1 0 00-.894.553L7.382 4H4a1 1 0 000 2v10a2 2 0 002 2h8a2 2 0 002-2V6a1 1 0 100-2h-3.382l-.724-1.447A1 1 0 0011 2H9zM7 8a1 1 0 012 0v6a1 1 0 11-2 0V8zm5-1a1 1 0 00-1 1v6a1 1 0 102 0V8a1 1 0 00-1-1z" clip-rule="evenodd" />
              </svg>
            </button>
            <button
              @click="selectedUser = null"
              class="p-2 rounded-full hover:bg-gray-100 transition-colors"
              title="Cerrar chat"
            >
              <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 text-gray-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <line x1="18" y1="6" x2="6" y2="18"></line>
                <line x1="6" y1="6" x2="18" y2="18"></line>
              </svg>
            </button>
          </div>
        </div>

        <!-- Mensajes -->
        <div ref="messagesContainer" class="flex-1 overflow-y-auto p-4 space-y-4 bg-gray-50">
          <div
            v-for="message in messages"
            :key="message.id"
            class="flex"
            :class="{ 'justify-end': message.sender === 'me', 'justify-start': message.sender === 'them' }"
          >
            <div
              class="max-w-[70%] p-3 rounded-lg"
              :class="{
                'bg-blue-100 text-blue-900': message.sender === 'me',
                'bg-white text-gray-900 border border-gray-200': message.sender === 'them'
              }"
            >
              <p>{{ message.text }}</p>
              <p
                class="text-xs mt-1"
                :class="{ 'text-blue-700': message.sender === 'me', 'text-gray-500': message.sender === 'them' }"
              >
                {{ message.timestamp }}
              </p>
            </div>
          </div>
        </div>

        <!-- Entrada de mensaje -->
        <form @submit.prevent="sendMessage" class="p-4 border-t border-gray-200 bg-white">
          <div class="flex space-x-2">
            <input
              v-model="newMessage"
              type="text"
              placeholder="Escribe un mensaje..."
              class="flex-1 px-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              :disabled="selectedUser.sessionStatus === 'pending'"
            />
            <button
              type="submit"
              class="p-2 bg-blue-500 text-white rounded-md hover:bg-blue-600 focus:outline-none focus:ring-2 focus:ring-blue-500"
              :disabled="selectedUser.sessionStatus === 'pending'"
              :class="{ 'opacity-50 cursor-not-allowed': selectedUser.sessionStatus === 'pending' }"
            >
              <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <line x1="22" y1="2" x2="11" y2="13"></line>
                <polygon points="22 2 15 22 11 13 2 9 22 2"></polygon>
              </svg>
            </button>
          </div>
          <div v-if="selectedUser.sessionStatus === 'pending'" class="mt-2 text-xs text-yellow-600 text-center">
            Esperando a que se establezca la sesión segura para enviar mensajes
          </div>
        </form>
      </template>
      <div v-else class="flex items-center justify-center h-full">
        <p class="text-gray-500">Selecciona un chat para comenzar</p>
      </div>
    </div>

    <!-- Vista móvil del chat -->
    <div v-if="isMobile && selectedUser" class="fixed inset-0 z-50 md:hidden bg-white flex flex-col">
      <!-- Cabecera del chat móvil -->
      <div class="flex items-center p-4 border-b border-gray-200 bg-white">
        <button @click="selectedUser = null" class="mr-2 p-1 rounded-full hover:bg-gray-100">
          <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <line x1="19" y1="12" x2="5" y2="12"></line>
            <polyline points="12 19 5 12 12 5"></polyline>
          </svg>
        </button>
        <div class="flex items-center">
          <div class="h-8 w-8 rounded-full bg-gray-200 flex items-center justify-center overflow-hidden">
            <img :src="selectedUser.avatar" :alt="selectedUser.name" class="h-full w-full object-cover" />
          </div>
          <div class="ml-2">
            <h2 class="text-base font-semibold">{{ selectedUser.name }}</h2>
            <!-- Indicador de estado de sesión -->
            <div v-if="selectedUser.sessionStatus === 'active'" class="flex items-center text-xs text-green-600">
              <svg xmlns="http://www.w3.org/2000/svg" class="h-3 w-3 mr-1" viewBox="0 0 20 20" fill="currentColor">
                <path fill-rule="evenodd" d="M5 9V7a5 5 0 0110 0v2a2 2 0 012 2v5a2 2 0 01-2 2H5a2 2 0 01-2-2v-5a2 2 0 012-2zm8-2v2H7V7a3 3 0 016 0z" clip-rule="evenodd" />
              </svg>
              <span>Sesión segura activa</span>
            </div>
            <div v-else-if="selectedUser.sessionStatus === 'pending'" class="flex items-center text-xs text-yellow-600">
              <svg xmlns="http://www.w3.org/2000/svg" class="h-3 w-3 mr-1" viewBox="0 0 20 20" fill="currentColor">
                <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm1-12a1 1 0 10-2 0v4a1 1 0 00.293.707l2.828 2.829a1 1 0 101.415-1.415L11 9.586V6z" clip-rule="evenodd" />
              </svg>
              <span>Sesión pendiente</span>
            </div>
          </div>
        </div>
        <!-- Botón para eliminar sesión y mensajes (móvil) -->
        <button
          v-if="selectedUser.sessionStatus === 'active'"
          @click="confirmDeleteSession"
          class="ml-auto p-2 rounded-full hover:bg-red-100 transition-colors text-red-500"
          title="Eliminar conversación"
        >
          <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
            <path fill-rule="evenodd" d="M9 2a1 1 0 00-.894.553L7.382 4H4a1 1 0 000 2v10a2 2 0 002 2h8a2 2 0 002-2V6a1 1 0 100-2h-3.382l-.724-1.447A1 1 0 0011 2H9zM7 8a1 1 0 012 0v6a1 1 0 11-2 0V8zm5-1a1 1 0 00-1 1v6a1 1 0 102 0V8a1 1 0 00-1-1z" clip-rule="evenodd" />
          </svg>
        </button>
      </div>

      <!-- Mensajes (móvil) -->
      <div ref="mobileMessagesContainer" class="flex-1 overflow-y-auto p-4 space-y-4 bg-gray-50">
        <div
          v-for="message in messages"
          :key="message.id"
          class="flex"
          :class="{ 'justify-end': message.sender === 'me', 'justify-start': message.sender === 'them' }"
        >
          <div
            class="max-w-[80%] p-3 rounded-lg"
            :class="{
              'bg-blue-100 text-blue-900': message.sender === 'me',
              'bg-white text-gray-900 border border-gray-200': message.sender === 'them'
            }"
          >
            <p>{{ message.text }}</p>
            <p
              class="text-xs mt-1"
              :class="{ 'text-blue-700': message.sender === 'me', 'text-gray-500': message.sender === 'them' }"
            >
              {{ message.timestamp }}
            </p>
          </div>
        </div>
      </div>

      <!-- Entrada de mensaje (móvil) -->
      <form @submit.prevent="sendMessage" class="p-3 border-t border-gray-200 bg-white">
        <div class="flex space-x-2">
          <input
            v-model="newMessage"
            type="text"
            placeholder="Escribe un mensaje..."
            class="flex-1 px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            :disabled="selectedUser.sessionStatus === 'pending'"
          />
          <button
            type="submit"
            class="p-2 bg-blue-500 text-white rounded-md hover:bg-blue-600 focus:outline-none focus:ring-2 focus:ring-blue-500"
            :disabled="selectedUser.sessionStatus === 'pending'"
            :class="{ 'opacity-50 cursor-not-allowed': selectedUser.sessionStatus === 'pending' }"
          >
            <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <line x1="22" y1="2" x2="11" y2="13"></line>
              <polygon points="22 2 15 22 11 13 2 9 22 2"></polygon>
            </svg>
          </button>
        </div>
        <div v-if="selectedUser.sessionStatus === 'pending'" class="mt-2 text-xs text-yellow-600 text-center">
          Esperando a que se establezca la sesión segura para enviar mensajes
        </div>
      </form>
    </div>

    <!-- Modal de confirmación para eliminar sesión -->
    <div v-if="showDeleteConfirmation" class="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50">
      <div class="bg-white rounded-lg p-6 max-w-md w-full mx-4">
        <h3 class="text-lg font-medium text-gray-900 mb-4">Eliminar conversación</h3>
        <p class="text-gray-600 mb-6">
          ¿Estás seguro de que deseas eliminar esta conversación? Se borrarán todos los mensajes y la sesión con este usuario. Esta acción no se puede deshacer.
        </p>
        <div class="flex justify-end space-x-3">
          <button
            @click="showDeleteConfirmation = false"
            class="px-4 py-2 bg-gray-200 text-gray-800 rounded-md hover:bg-gray-300 transition-colors"
          >
            Cancelar
          </button>
          <button
            @click="deleteSession"
            class="px-4 py-2 bg-red-500 text-white rounded-md hover:bg-red-600 transition-colors"
          >
            Eliminar
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import {ref, onMounted, watch, nextTick} from 'vue';
import axios from '@/axios';

export default {
  setup() {
    const selectedUser = ref(null);
    const messages = ref([]);
    const newMessage = ref('');
    const messagesContainer = ref(null);
    const mobileMessagesContainer = ref(null);
    const isAddFriendMenuOpen = ref(false);
    const isProfileMenuOpen = ref(false);
    const newFriendName = ref("");
    const potentialFriends = ref([]);
    const incomingPendingSessions = ref([]);
    const outgoingPendingSessions = ref([]);
    const activeUsers = ref([]);
    const isMobile = ref(window.innerWidth < 768);
    const showDeleteConfirmation = ref(false);

    // Detectar cambios en el tamaño de la ventana
    window.addEventListener('resize', () => {
      isMobile.value = window.innerWidth < 768;
    });

    // Cargar sesiones pendientes recibidas
    const loadIncomingPendingSessions = async () => {
      try {
        const response = await axios.get('/pending_sessions/');
        incomingPendingSessions.value = response.data.pending_sessions;
      } catch (error) {
        console.error('Error al cargar sesiones pendientes:', error);
      }
    };

    // Cargar sesiones pendientes enviadas
    const loadOutgoingPendingSessions = async () => {
      try {
        const response = await axios.get('/outgoing_pending_sessions/');
        outgoingPendingSessions.value = response.data.pending_sessions;
      } catch (error) {
        console.error('Error al cargar sesiones pendientes enviadas:', error);
      }
    };

    // Cargar conversaciones activas
    const loadActiveConversations = async () => {
      try {
        const response = await axios.get('/get_conversations_ephemeral/');
        activeUsers.value = response.data.conversations.map(conv => ({
          id: conv.peer_id,
          name: conv.peer_username,
          avatar: `/placeholder.svg?height=40&width=40&text=${conv.peer_username.charAt(0).toUpperCase()}`,
          lastMessage: conv.last_message || 'No hay mensajes',
          lastMessageTime: conv.last_message_time ? new Date(conv.last_message_time).toLocaleTimeString([], {
            hour: '2-digit',
            minute: '2-digit'
          }) : '',
          unread: 0,
          sessionId: conv.session_id,
          sessionStatus: 'active'
        }));
      } catch (error) {
        console.error('Error al cargar conversaciones activas:', error);
      }
    };

    // Cargar todos los datos
    const loadAllData = () => {
      loadIncomingPendingSessions();
      loadOutgoingPendingSessions();
      loadActiveConversations();
    };

    // Seleccionar usuario para chat
    const selectUser = async (user) => {
      selectedUser.value = user;
      await loadMessages();

      // Scroll al final de los mensajes
      nextTick(() => {
        if (messagesContainer.value) {
          messagesContainer.value.scrollTop = messagesContainer.value.scrollHeight;
        }
        if (mobileMessagesContainer.value) {
          mobileMessagesContainer.value.scrollTop = mobileMessagesContainer.value.scrollHeight;
        }
      });
    };

    // Cargar mensajes
    const loadMessages = async () => {
      if (!selectedUser.value) return;

      try {
        // Usar el nuevo endpoint para obtener todos los mensajes con el usuario
        const response = await axios.get(`/get_all_messages_with_user/${selectedUser.value.id}`);

        messages.value = response.data.messages.map(msg => ({
          id: msg.id,
          text: msg.message,
          sender: msg.sender_id === selectedUser.value.id ? 'them' : 'me',
          timestamp: new Date(msg.created_at).toLocaleString([], {
            hour: '2-digit',
            minute: '2-digit',
            day: '2-digit',
            month: '2-digit',
            year: '2-digit'
          })
        }));
      } catch (error) {
        console.error('Error al cargar mensajes:', error);
      }
    };

    // Enviar mensaje
    const sendMessage = async () => {
      if (!newMessage.value.trim() || !selectedUser.value || selectedUser.value.sessionStatus !== 'active') return;

      try {
        await axios.post('/send_message_ephemeral/', {
          session_id: selectedUser.value.sessionId,
          message: newMessage.value
        });

        // Recargar mensajes después de enviar
        await loadMessages();
        newMessage.value = '';

        // Scroll al final de los mensajes
        nextTick(() => {
          if (messagesContainer.value) {
            messagesContainer.value.scrollTop = messagesContainer.value.scrollHeight;
          }
          if (mobileMessagesContainer.value) {
            mobileMessagesContainer.value.scrollTop = mobileMessagesContainer.value.scrollHeight;
          }
        });
      } catch (error) {
        console.error('Error al enviar mensaje:', error);
        alert('Error al enviar mensaje. Por favor, intenta de nuevo.');
      }
    };

    // Aceptar sesión
    const acceptSession = async (sessionId, initiatorId) => {
      try {
        await axios.post(`/accept_session/${sessionId}`);

        // Actualizar listas
        loadAllData();

        // Si el usuario ya estaba seleccionado, actualizar su estado
        if (selectedUser.value && selectedUser.value.id === initiatorId) {
          selectedUser.value.sessionStatus = 'active';
          selectedUser.value.sessionId = sessionId;
        }
      } catch (error) {
        console.error('Error al aceptar sesión:', error);
        alert('Error al aceptar la sesión. Por favor, intenta de nuevo.');
      }
    };

    // Rechazar sesión
    const rejectSession = async (sessionId) => {
      try {
        await axios.post(`/reject_session/${sessionId}`);

        // Actualizar lista de sesiones pendientes
        loadIncomingPendingSessions();
      } catch (error) {
        console.error('Error al rechazar sesión:', error);
        alert('Error al rechazar la sesión. Por favor, intenta de nuevo.');
      }
    };

    // Cancelar sesión pendiente enviada
    const cancelSession = async (sessionId) => {
      try {
        await axios.post(`/cancel_session/${sessionId}`);

        // Actualizar lista de sesiones pendientes enviadas
        loadOutgoingPendingSessions();
      } catch (error) {
        console.error('Error al cancelar sesión:', error);
        alert('Error al cancelar la sesión. Por favor, intenta de nuevo.');
      }
    };

    // Confirmar eliminación de sesión
    const confirmDeleteSession = () => {
      showDeleteConfirmation.value = true;
    };

    // Eliminar sesión y mensajes
    const deleteSession = async () => {
      if (!selectedUser.value || !selectedUser.value.sessionId) {
        showDeleteConfirmation.value = false;
        return;
      }

      try {
        await axios.delete(`/delete_session/${selectedUser.value.sessionId}`);

        // Cerrar modal
        showDeleteConfirmation.value = false;

        // Actualizar listas y cerrar chat
        loadAllData();
        selectedUser.value = null;
      } catch (error) {
        console.error('Error al eliminar sesión:', error);
        alert('Error al eliminar la conversación. Por favor, intenta de nuevo.');
        showDeleteConfirmation.value = false;
      }
    };

    // Alternar menú de añadir amigos
    const toggleAddFriendMenu = () => {
      isAddFriendMenuOpen.value = !isAddFriendMenuOpen.value;
      if (isAddFriendMenuOpen.value) {
        isProfileMenuOpen.value = false;
      }
    };

    // Alternar menú de perfil
    const toggleProfileMenu = () => {
      isProfileMenuOpen.value = !isProfileMenuOpen.value;
      if (isProfileMenuOpen.value) {
        isAddFriendMenuOpen.value = false;
      }
    };

    // Buscar amigos
    const addFriend = async () => {
      if (!newFriendName.value.trim()) return;

      try {
        const response = await axios.get(`/search_user/${newFriendName.value}`);
        potentialFriends.value = response.data.users.map(user => ({
          ...user,
          avatar: `/placeholder.svg?height=40&width=40&text=${user.username.charAt(0).toUpperCase()}`
        }));
      } catch (error) {
        console.error('Error al buscar usuarios:', error);
      }
    };

    // Seleccionar amigo de la lista
    const selectFriendFromList = async (friend) => {
      try {
        // Verificar si ya existe una sesión con este usuario
        const existingUser = activeUsers.value.find(u => u.id === friend.id);
        if (existingUser) {
          // Ya existe una sesión activa, seleccionarla
          selectUser(existingUser);
          isAddFriendMenuOpen.value = false;
          return;
        }

        // Verificar si ya hay una sesión pendiente enviada a este usuario
        const pendingOutgoing = outgoingPendingSessions.value.find(s => s.receiver_id === friend.id);
        if (pendingOutgoing) {
          alert('Ya has enviado una solicitud de sesión a este usuario.');
          isAddFriendMenuOpen.value = false;
          return;
        }

        // Verificar si ya hay una sesión pendiente recibida de este usuario
        const pendingIncoming = incomingPendingSessions.value.find(s => s.initiator_id === friend.id);
        if (pendingIncoming) {
          alert('Este usuario ya te ha enviado una solicitud de sesión. Revisa tus solicitudes pendientes.');
          isAddFriendMenuOpen.value = false;
          return;
        }

        // Iniciar nueva sesión
        await axios.post(`/initiate_session/${friend.id}`);

        // Actualizar listas
        loadAllData();

        // Cerrar menú
        isAddFriendMenuOpen.value = false;
        newFriendName.value = '';
        potentialFriends.value = [];

        // Mostrar mensaje de éxito
        alert(`Solicitud de sesión enviada a ${friend.username}. Esperando aceptación.`);
      } catch (error) {
        console.error('Error al iniciar sesión:', error);
        if (error.response && error.response.data && error.response.data.detail) {
          alert(error.response.data.detail);
        } else {
          alert('Error al iniciar sesión. Por favor, intenta de nuevo.');
        }
      }
    };

    // Ver perfil
    const viewProfile = () => {
      isProfileMenuOpen.value = false;
      // Implementar vista de perfil
    };

    // Cerrar sesión
    const logout = async () => {
      try {
        // Eliminar token de autenticación
        localStorage.removeItem('access_token');
        // Redirigir a la página de inicio de sesión
        window.location.href = '/';
      } catch (error) {
        console.error('Error al cerrar sesión:', error);
      }
    };

    // Cargar datos al montar el componente
    onMounted(() => {
      loadAllData();

      // Configurar intervalo para actualizar datos
      const intervalId = setInterval(loadAllData, 10000);

      // Limpiar intervalo al desmontar
      return () => clearInterval(intervalId);
    });

    // Observar cambios en los mensajes para hacer scroll
    watch(messages, () => {
      nextTick(() => {
        if (messagesContainer.value) {
          messagesContainer.value.scrollTop = messagesContainer.value.scrollHeight;
        }
        if (mobileMessagesContainer.value) {
          mobileMessagesContainer.value.scrollTop = mobileMessagesContainer.value.scrollHeight;
        }
      });
    });

    // Cerrar menús al hacer clic fuera
    onMounted(() => {
      document.addEventListener('click', (event) => {
        //const addFriendMenu = document.querySelector('.relative button[title="Añadir amigos"]');
        const profileMenu = document.querySelector('.relative button[title="Mi perfil"]');

        //if (addFriendMenu && !addFriendMenu.contains(event.target) && isAddFriendMenuOpen.value) {
        //  isAddFriendMenuOpen.value = false;
        //}

        if (profileMenu && !profileMenu.contains(event.target) && isProfileMenuOpen.value) {
          isProfileMenuOpen.value = false;
        }
      });
    });

    return {
      selectedUser,
      messages,
      newMessage,
      messagesContainer,
      mobileMessagesContainer,
      isAddFriendMenuOpen,
      isProfileMenuOpen,
      newFriendName,
      potentialFriends,
      incomingPendingSessions,
      outgoingPendingSessions,
      activeUsers,
      isMobile,
      showDeleteConfirmation,
      selectUser,
      sendMessage,
      acceptSession,
      rejectSession,
      cancelSession,
      confirmDeleteSession,
      deleteSession,
      toggleAddFriendMenu,
      toggleProfileMenu,
      addFriend,
      selectFriendFromList,
      viewProfile,
      logout
    };
  }
};
</script>

<style scoped>
/* Estilos adicionales si son necesarios */
</style>