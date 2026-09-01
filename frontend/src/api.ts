import axios from 'axios'

declare module 'axios' {
  export interface InternalAxiosRequestConfig {
    _retryCount?: number
    _authRetry?: boolean
    _sessionGeneration?: number
  }
}

const baseURL = import.meta.env.VITE_API_BASE_URL || '/api/v1'

export function apiEndpoint(path: string): string {
  const normalizedBase = baseURL.replace(/\/$/, '')
  const normalizedPath = path.startsWith('/') ? path : `/${path}`
  return new URL(`${normalizedBase}${normalizedPath}`, window.location.origin).toString()
}

export const api = axios.create({
  baseURL,
  timeout: 15000,
  withCredentials: true,
})

const refreshClient = axios.create({ baseURL, timeout: 15000, withCredentials: true })
let refreshPromise: Promise<string> | null = null
let refreshController: AbortController | null = null
let accessToken: string | null = null
let sessionGeneration = 0
let sessionController = new AbortController()
const retryableReadStatuses = new Set([408, 425, 429, 500, 502, 503, 504])

function retryDelay(error: any, attempt: number): number {
  const exponential = Math.min(1000 * 2 ** (attempt - 1), 15_000)
  const retryAfter = error.response?.headers?.['retry-after']
  if (typeof retryAfter !== 'string') return exponential
  const seconds = Number(retryAfter)
  if (Number.isFinite(seconds) && seconds >= 0) {
    return Math.max(exponential, Math.min(seconds * 1000, 30_000))
  }
  const dateDelay = Date.parse(retryAfter) - Date.now()
  return Number.isFinite(dateDelay) && dateDelay > 0
    ? Math.max(exponential, Math.min(dateDelay, 30_000))
    : exponential
}

export function setAccessToken(token: string): void {
  accessToken = token
}

export function getAccessToken(): string | null {
  return accessToken
}

export function clearAccessToken(): void {
  accessToken = null
  sessionGeneration += 1
  sessionController.abort()
  sessionController = new AbortController()
  refreshController?.abort()
}

function waitBeforeRetry(config: any, milliseconds: number | null): Promise<void> {
  const signal = config.signal as AbortSignal | undefined
  return new Promise((resolve, reject) => {
    let timer: number | null = null
    const cleanup = () => {
      if (timer !== null) window.clearTimeout(timer)
      window.removeEventListener('online', complete)
      signal?.removeEventListener('abort', cancel)
    }
    const complete = () => {
      cleanup()
      resolve()
    }
    const cancel = () => {
      cleanup()
      reject(new axios.CanceledError('stale authentication session'))
    }
    if (signal?.aborted) {
      cancel()
      return
    }
    signal?.addEventListener('abort', cancel, { once: true })
    if (milliseconds === null) {
      window.addEventListener('online', complete, { once: true })
    } else {
      timer = window.setTimeout(complete, milliseconds)
    }
  })
}

export async function refreshAccessToken(): Promise<string> {
  if (!refreshPromise) {
    const generation = sessionGeneration
    const controller = new AbortController()
    refreshController = controller
    refreshPromise = refreshClient.post('/auth/refresh', undefined, {
      signal: controller.signal,
    }).then(({ data }) => {
      if (generation !== sessionGeneration) {
        throw new axios.CanceledError('stale authentication session')
      }
      setAccessToken(data.access_token)
      localStorage.setItem('mineguard_user', JSON.stringify(data.user))
      return data.access_token as string
    }).finally(() => {
      refreshPromise = null
      if (refreshController === controller) refreshController = null
    })
  }
  return refreshPromise
}

api.interceptors.request.use((config) => {
  config._sessionGeneration ??= sessionGeneration
  config.signal ??= sessionController.signal
  const token = getAccessToken()
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

api.interceptors.response.use(
  (response) => {
    if (response.config._sessionGeneration !== sessionGeneration) {
      return Promise.reject(new axios.CanceledError('stale authentication session'))
    }
    window.dispatchEvent(new Event('mineguard:connection-restored'))
    return response
  },
  async (error) => {
    const config = error.config
    if (config && config._sessionGeneration !== sessionGeneration) {
      return Promise.reject(new axios.CanceledError('stale authentication session'))
    }
    const authEndpoint = ['/auth/login', '/auth/refresh', '/auth/logout'].some((path) => config?.url?.includes(path))
    if (error.response?.status === 401 && config && !authEndpoint && !config._authRetry) {
      config._authRetry = true
      try {
        const token = await refreshAccessToken()
        config.headers.Authorization = `Bearer ${token}`
        return api(config)
      } catch (refreshError: any) {
        if ([401, 403].includes(refreshError.response?.status)) {
          clearAccessToken()
          localStorage.removeItem('mineguard_user')
          window.dispatchEvent(new Event('mineguard:unauthorized'))
        } else {
          window.dispatchEvent(new Event('mineguard:connection-lost'))
        }
        return Promise.reject(refreshError)
      }
    }

    const method = config?.method?.toLowerCase()
    const retryableStatus = !error.response || retryableReadStatuses.has(error.response.status)
    const retryableMethod = method === 'get' || method === 'head'
    if (config && retryableMethod && retryableStatus && (config._retryCount || 0) < 5) {
      config._retryCount = (config._retryCount || 0) + 1
      window.dispatchEvent(new CustomEvent('mineguard:reconnecting', { detail: config._retryCount }))
      if (!navigator.onLine) {
        await waitBeforeRetry(config, null)
      } else {
        const delay = retryDelay(error, config._retryCount)
        await waitBeforeRetry(config, delay + Math.random() * 350)
      }
      if (config._sessionGeneration !== sessionGeneration) {
        return Promise.reject(new axios.CanceledError('stale authentication session'))
      }
      return api(config)
    }
    if (retryableStatus) window.dispatchEvent(new Event('mineguard:connection-lost'))
    return Promise.reject(error)
  },
)
