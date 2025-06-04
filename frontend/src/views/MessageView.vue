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

      <!-- Mensaje de bienvenida cuando no hay chat seleccionado -->
      <div v-else class="flex flex-col items-center justify-center h-full text-center p-8">
        <div class="w-24 h-24 bg-blue-100 rounded-full flex items-center justify-center mb-4">
          <svg xmlns="http://www.w3.org/2000/svg" class="h-12 w-12 text-blue-500" viewBox="0 0 20 20" fill="currentColor">
            <path fill-rule="evenodd" d="M18 10c0 3.866-3.582 7-8 7a8.841 8.841 0 01-4.083-.98L2 17l1.338-3.123C2.493 12.767 2 11.434 2 10c0-3.866 3.582-7 8-7s8 3.134 8 7zM7 9H5v2h2V9zm8 0h-2v2h2V9zM9 9h2v2H9V9z" clip-rule="evenodd" />
          </svg>
        </div>
        <h2 class="text-xl font-semibold text-gray-800 mb-2">Bienvenido a GodXat</h2>
        <p class="text-gray-600 max-w-md">
          Selecciona una conversación existente o inicia una nueva para comenzar a chatear de forma segura.
        </p>
      </div>
    </div>

    <!-- Área de chat (móvil) -->
    <div
      v-if="isMobile && selectedUser"
      class="fixed inset-0 bg-white z-50 flex flex-col"
    >
      <!-- Cabecera del chat móvil -->
      <div class="flex items-center justify-between p-4 border-b border-gray-200 bg-white">
        <div class="flex items-center">
          <button
            @click="selectedUser = null"
            class="p-2 mr-2 rounded-full hover:bg-gray-100 transition-colors"
          >
            <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 text-gray-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <line x1="19" y1="12" x2="5" y2="12"></line>
              <polyline points="12 19 5 12 12 5"></polyline>
            </svg>
          </button>
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
        <div>
          <!-- Botón para eliminar sesión y mensajes (móvil) -->
          <button
            v-if="selectedUser.sessionStatus === 'active'"
            @click="confirmDeleteSession"
            class="p-2 rounded-full hover:bg-red-100 transition-colors text-red-500"
            title="Eliminar conversación"
          >
            <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
              <path fill-rule="evenodd" d="M9 2a1 1 0 00-.894.553L7.382 4H4a1 1 0 000 2v10a2 2 0 002 2h8a2 2 0 002-2V6a1 1 0 100-2h-3.382l-.724-1.447A1 1 0 0011 2H9zM7 8a1 1 0 012 0v6a1 1 0 11-2 0V8zm5-1a1 1 0 00-1 1v6a1 1 0 102 0V8a1 1 0 00-1-1z" clip-rule="evenodd" />
            </svg>
          </button>
        </div>
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
    </div>

    <!-- Modal de confirmación para eliminar sesión -->
    <div v-if="showDeleteConfirmation" class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div class="bg-white rounded-lg p-6 max-w-sm mx-4">
        <h3 class="text-lg font-medium text-gray-900 mb-4">Eliminar conversación</h3>
        <p class="text-gray-600 mb-6">
          ¿Estás seguro de que deseas eliminar esta conversación? Esta acción no se puede deshacer y se perderán todos
          los mensajes.
        </p>
        <div class="flex justify-end space-x-3">
          <button
              @click="showDeleteConfirmation = false"
              class="px-4 py-2 border border-gray-300 rounded-md text-gray-700 hover:bg-gray-50"
          >
            Cancelar
          </button>
          <button
              @click="deleteSession"
              class="px-4 py-2 bg-red-500 text-white rounded-md hover:bg-red-600"
          >
            Eliminar
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import { ref, onMounted, nextTick } from 'vue';
import { useRouter } from 'vue-router';
import authService from '@/services/auth_service'
import messageService from '@/services/message_service';

export default {
  name: 'MessageView',
  setup() {
    const router = useRouter();

    // Estado de la interfaz
    const isAddFriendMenuOpen = ref(false);
    const isProfileMenuOpen = ref(false);
    const newFriendName = ref('');
    const potentialFriends = ref([]);
    const selectedUser = ref(null);
    const newMessage = ref('');
    const messages = ref([]);
    const messagesContainer = ref(null);
    const activeUsers = ref([]);
    const incomingPendingSessions = ref([]);
    const outgoingPendingSessions = ref([]);

    // Cargar datos al montar el componente
    onMounted(async () => {
      try {
        // Verificar si hay token de autenticación
        const token = localStorage.getItem('token');
        if (!token) {
          router.push('/');
          return;
        }
        messageService.initMessageService();

        await authService.checkAndCompleteSessions();

        // Cargar sesiones pendientes
        await loadPendingSessions();

        // Cargar conversaciones activas
        await loadConversations();

      } catch (error) {
        console.error('Error al cargar datos iniciales:', error);
        if (error.response?.status === 401) {
          // Token expirado o inválido
          localStorage.removeItem('token');
          router.push('/');
        }
      }
    });

    // Funciones para menús desplegables
    const toggleAddFriendMenu = () => {
      isAddFriendMenuOpen.value = !isAddFriendMenuOpen.value;
      if (isAddFriendMenuOpen.value) {
        isProfileMenuOpen.value = false;
      }
    };

    const toggleProfileMenu = () => {
      isProfileMenuOpen.value = !isProfileMenuOpen.value;
      if (isProfileMenuOpen.value) {
        isAddFriendMenuOpen.value = false;
      }
    };

    // Función para buscar amigos
    const addFriend = async () => {
      if (!newFriendName.value.trim()) return;

      try {
        const response = await authService.searchUser(newFriendName.value);

        // Obtener el usuario actual del localStorage (puede ser JSON string)
        const currentUserRaw = localStorage.getItem("currentUser");
        const currentUser = currentUserRaw ? JSON.parse(currentUserRaw) : null;

        // Filtrar el usuario actual de la lista
        potentialFriends.value = (response.users || []).filter(
          user => user.username !== currentUser?.username
        );
      } catch (error) {
        console.error('Error al buscar usuarios:', error);
        alert('No se pudo buscar usuarios. Inténtalo de nuevo.');
      }
    };

    // Función para seleccionar un amigo de la lista
    const selectFriendFromList = async (friend) => {
      try {
        // Iniciar una sesión con el usuario seleccionado
        await authService.initiateSession(friend.id);

        // Recargar sesiones pendientes
        await loadPendingSessions();

        // Cerrar el menú
        isAddFriendMenuOpen.value = false;
        newFriendName.value = '';
        potentialFriends.value = [];

        alert(`Se ha enviado una solicitud de chat a ${friend.username}`);
      } catch (error) {
        console.error('Error al iniciar sesión:', error);
        alert('No se pudo iniciar la sesión. Inténtalo de nuevo.');
      }
    };

    // Función para cargar sesiones pendientes
    const loadPendingSessions = async () => {
      try {
        const pendingSessions = await authService.getPendingSessions();
        const outPendingSessions = await  authService.getOutComingPendingSessions();

        console.log(pendingSessions)
        console.log(outPendingSessions)

        // Separar sesiones pendientes entrantes y salientes
        incomingPendingSessions.value = pendingSessions.pending_sessions

        outgoingPendingSessions.value = outPendingSessions.out_pending_sessions
      } catch (error) {
        console.error('Error al cargar sesiones pendientes:', error);
      }
    };

    // Función para cargar conversaciones activas
    const loadConversations = async () => {
      try {
        const conversations = await messageService.getConversations();

        // Transformar las conversaciones al formato esperado por la UI
        activeUsers.value = conversations.conversations.map(conv => ({
          id: conv.peer_id,
          name: conv.peer_username,
          avatar: `/placeholder.svg?height=40&width=40&text=${conv.peer_username.charAt(0)}`,
          lastMessage: conv.last_message || 'No hay mensajes',
          lastMessageTime: formatDate(conv.last_message_time),
          unread: conv.unread_count || 0,
          sessionId: conv.session_id,
          sessionStatus: 'active'
        }));
      } catch (error) {
        console.error('Error al cargar conversaciones:', error);
      }
    };

    // Función para aceptar una sesión pendiente
    const acceptSession = async (sessionId, initiatorId) => {
      try {
        await authService.acceptSession(sessionId);

        // Recargar sesiones pendientes y conversaciones
        await loadPendingSessions();
        await loadConversations();

        // Seleccionar automáticamente la conversación aceptada
        const newConversation = activeUsers.value.find(user => user.id === initiatorId);
        if (newConversation) {
          selectUser(newConversation);
        }
      } catch (error) {
        console.error('Error al aceptar sesión:', error);
        alert('No se pudo aceptar la sesión. Inténtalo de nuevo.');
      }
    };

    // Función para rechazar una sesión pendiente
    const rejectSession = async (sessionId) => {
      try {
        // Implementar rechazo de sesión
        await authService.rejectSession(sessionId);

        // Por ahora, solo eliminamos de la lista local
        incomingPendingSessions.value = incomingPendingSessions.value.filter(
          session => session.session_id !== sessionId
        );
      } catch (error) {
        console.error('Error al rechazar sesión:', error);
        alert('No se pudo rechazar la sesión. Inténtalo de nuevo.');
      }
    };

    // Función para cancelar una sesión pendiente enviada
    const cancelSession = async (sessionId) => {
      try {
        // Implementar cancelación de sesión
        await authService.cancelSession(sessionId);

        outgoingPendingSessions.value = outgoingPendingSessions.value.filter(
          session => session.session_id !== sessionId
        );

      } catch (error) {
        console.error('Error al cancelar sesión:', error);
        alert('No se pudo cancelar la sesión. Inténtalo de nuevo.');
      }
    };

    // Función para seleccionar un usuario para chatear
    const selectUser = async (user) => {
      selectedUser.value = user;

      // Cargar mensajes
      await loadMessages(user.sessionId);

      // Desplazar al final de los mensajes
      await nextTick();
      if (messagesContainer.value) {
        messagesContainer.value.scrollTop = messagesContainer.value.scrollHeight;
      }
    };

    // Función para cargar mensajes de una sesión
    const loadMessages = async (sessionId) => {
      try {
        const response = await messageService.getMessages(sessionId);

        // Transformar los mensajes al formato esperado por la UI
        messages.value = response.messages.map(msg => ({
          id: msg.id,
          text: msg.message,
          sender: msg.sender_id === authService.currentUser.id ? 'me' : 'them',
          timestamp: formatDate(msg.timestamp)
        }));
      } catch (error) {
        console.error('Error al cargar mensajes:', error);
        messages.value = [];
      }
    };

    // Función para enviar un mensaje
    const sendMessage = async () => {
      if (!newMessage.value.trim() || !selectedUser.value) return;

      try {
        // Enviar mensaje
        await messageService.sendMessage(selectedUser.value.sessionId, newMessage.value);

        // Añadir mensaje a la lista local
        messages.value.push({
          id: Date.now(),
          text: newMessage.value,
          sender: 'me',
          timestamp: formatDate(new Date())
        });

        // Limpiar campo de mensaje
        newMessage.value = '';

        // Desplazar al final de los mensajes
        await nextTick();
        if (messagesContainer.value) {
          messagesContainer.value.scrollTop = messagesContainer.value.scrollHeight;
        }
      } catch (error) {
        console.error('Error al enviar mensaje:', error);
        alert('No se pudo enviar el mensaje. Inténtalo de nuevo.');
      }
    };

    // Función para confirmar eliminación de sesión
    const confirmDeleteSession = () => {
      if (confirm('¿Estás seguro de que deseas eliminar esta conversación? Todos los mensajes se perderán.')) {
        deleteSession();
      }
    };

    // Función para eliminar una sesión
    const deleteSession = async () => {
      if (!selectedUser.value) return;

      try {
        // Implementar eliminación de sesión
        // await authService.deleteSession(selectedUser.value.sessionId);

        // Eliminar de la lista local
        activeUsers.value = activeUsers.value.filter(
          user => user.id !== selectedUser.value.id
        );

        // Deseleccionar usuario
        selectedUser.value = null;
      } catch (error) {
        console.error('Error al eliminar sesión:', error);
        alert('No se pudo eliminar la sesión. Inténtalo de nuevo.');
      }
    };

    // Función para ver perfil
    const viewProfile = () => {
      alert('Funcionalidad de perfil no implementada');
      isProfileMenuOpen.value = false;
    };

    // Función para cerrar sesión
    const logout = () => {
      //messageService.logout();
      authService.logout();
      messageService.logout();
      router.push('/');
    };

    // Función auxiliar para formatear fechas
    const formatDate = (dateString) => {
      if (!dateString) return '';

      const date = new Date(dateString);
      const now = new Date();

      // Si es hoy, mostrar solo la hora
      if (date.toDateString() === now.toDateString()) {
        return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
      }

      // Si es este año, mostrar día y mes
      if (date.getFullYear() === now.getFullYear()) {
        return date.toLocaleDateString([], { day: 'numeric', month: 'short' });
      }

      // Si es otro año, mostrar día, mes y año
      return date.toLocaleDateString([], { day: 'numeric', month: 'short', year: 'numeric' });
    };

    return {
      isAddFriendMenuOpen,
      isProfileMenuOpen,
      newFriendName,
      potentialFriends,
      selectedUser,
      newMessage,
      messages,
      messagesContainer,
      activeUsers,
      incomingPendingSessions,
      outgoingPendingSessions,
      toggleAddFriendMenu,
      toggleProfileMenu,
      addFriend,
      selectFriendFromList,
      acceptSession,
      rejectSession,
      cancelSession,
      selectUser,
      sendMessage,
      confirmDeleteSession,
      viewProfile,
      logout
    };
  }
}
</script>

<style scoped>
/* Estilos adicionales si son necesarios */
</style>