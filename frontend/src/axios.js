import axios from 'axios'

const instance = axios.create({
  baseURL: process.env.VUE_APP_API_URL,
})

// Añadir token a cada request
instance.interceptors.request.use(config => {
  const token = localStorage.getItem('token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// Manejar respuestas con error 401
instance.interceptors.response.use(
  response => response,
  async error => {
    if (error.response && error.response.status === 401) {
      // Aquí podrías redirigir al login o intentar refrescar token
      localStorage.removeItem('token')
      window.location.href = '/'  // redirige a login
    }
    return Promise.reject(error)
  }
)

export default instance
