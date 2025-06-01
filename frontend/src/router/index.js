import { createRouter, createWebHashHistory } from 'vue-router'
import LoginView from '@/views/LoginView.vue'
import MessageView from '@/views/MessageView.vue'
import RegisterView from '@/views/RegisterView.vue'

const router = createRouter({
  history: createWebHashHistory(),
  routes: [
    {
      path: '/',
      name: 'Login',
      component: LoginView
    },
    {
      path: '/register',
      name: 'Register',
      component: RegisterView
    },
    {
      path: '/message',
      name: 'Message',
      component: MessageView,
      meta: { requiresAuth: true }
    }
  ]
})

// 🔒 Middleware de navegación
router.beforeEach((to, from, next) => {
  const isAuthenticated = !!localStorage.getItem('access_token')

  if (to.meta.requiresAuth && !isAuthenticated) {
    next('/') // redirige al inicio si no hay token
  } else {
    next()
  }
})

export default router
