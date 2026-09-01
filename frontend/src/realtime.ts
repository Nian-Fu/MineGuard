import { apiEndpoint, getAccessToken, refreshAccessToken } from './api'

export interface RealtimeSignal {
  id: number
  topic: string
  area: string | null
  resource_id: string | null
  action: string
  created_at: string
}

const cursorKey = 'mineguard_realtime_cursor'
const maximumEventBufferBytes = 64 * 1024

function abortableDelay(milliseconds: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    if (signal.aborted) return resolve()
    const timer = window.setTimeout(done, milliseconds)
    signal.addEventListener('abort', done, { once: true })
    function done() {
      window.clearTimeout(timer)
      signal.removeEventListener('abort', done)
      resolve()
    }
  })
}

function waitUntilOnline(signal: AbortSignal): Promise<void> {
  if (navigator.onLine || signal.aborted) return Promise.resolve()
  return new Promise((resolve) => {
    window.addEventListener('online', done, { once: true })
    signal.addEventListener('abort', done, { once: true })
    function done() {
      window.removeEventListener('online', done)
      signal.removeEventListener('abort', done)
      resolve()
    }
  })
}

export function createRealtimeClient(onSignal: (signal: RealtimeSignal) => void) {
  let generation = 0
  let controller: AbortController | null = null

  function stop() {
    generation += 1
    controller?.abort()
    controller = null
  }

  function start() {
    stop()
    const currentGeneration = generation
    controller = new AbortController()
    void run(currentGeneration, controller.signal)
  }

  async function run(currentGeneration: number, signal: AbortSignal) {
    let attempt = 0
    while (generation === currentGeneration && !signal.aborted) {
      await waitUntilOnline(signal)
      if (signal.aborted || generation !== currentGeneration) return
      try {
        const headers: Record<string, string> = {
          Accept: 'text/event-stream',
          Authorization: `Bearer ${getAccessToken() || ''}`,
        }
        const cursor = sessionStorage.getItem(cursorKey)
        if (cursor) headers['Last-Event-ID'] = cursor
        const response = await fetch(apiEndpoint('/realtime/stream'), {
          headers,
          credentials: 'include',
          cache: 'no-store',
          signal,
        })
        if (response.status === 401) {
          await response.body?.cancel()
          try {
            await refreshAccessToken()
            continue
          } catch (error: any) {
            if ([401, 403].includes(error.response?.status)) {
              window.dispatchEvent(new Event('mineguard:unauthorized'))
              return
            }
            throw error
          }
        }
        if (response.status === 404) {
          await response.body?.cancel()
          await abortableDelay(30_000 + Math.random() * 500, signal)
          continue
        }
        if (!response.ok || !response.body) {
          await response.body?.cancel()
          throw new Error(`Realtime HTTP ${response.status}`)
        }

        attempt = 0
        window.dispatchEvent(new Event('mineguard:connection-restored'))
        const reader = response.body.getReader()
        const decoder = new TextDecoder()
        const encoder = new TextEncoder()
        let buffer = ''
        try {
          while (!signal.aborted) {
            const { value, done } = await reader.read()
            if (done) break
            buffer += decoder.decode(value, { stream: true })
            buffer = buffer.replace(/\r\n/g, '\n')
            let boundary = buffer.indexOf('\n\n')
            while (boundary >= 0) {
              consumeBlock(buffer.slice(0, boundary))
              buffer = buffer.slice(boundary + 2)
              boundary = buffer.indexOf('\n\n')
            }
            if (encoder.encode(buffer).byteLength > maximumEventBufferBytes) {
              throw new Error('Realtime event exceeds buffer limit')
            }
          }
        } finally {
          try { await reader.cancel() } catch { /* Connection already closed. */ }
          reader.releaseLock()
        }
        if (!signal.aborted) throw new Error('Realtime stream ended')
      } catch (error) {
        if (signal.aborted || generation !== currentGeneration) return
        attempt += 1
        window.dispatchEvent(
          new CustomEvent('mineguard:reconnecting', { detail: attempt }),
        )
        const delay = Math.min(1000 * 2 ** Math.min(attempt - 1, 5), 30_000)
        await abortableDelay(delay + Math.random() * 500, signal)
      }
    }
  }

  function consumeBlock(block: string) {
    if (!block || block.startsWith(':')) return
    let eventType = 'message'
    let id = ''
    const data: string[] = []
    for (const rawLine of block.split('\n')) {
      const line = rawLine.endsWith('\r') ? rawLine.slice(0, -1) : rawLine
      if (line.startsWith('event:')) eventType = line.slice(6).trim()
      else if (line.startsWith('id:')) id = line.slice(3).trim()
      else if (line.startsWith('data:')) data.push(line.slice(5).trimStart())
    }
    const validId = /^\d+$/.test(id) ? id : null
    if (eventType === 'ready' || !data.length) {
      if (validId) sessionStorage.setItem(cursorKey, validId)
      return
    }
    try {
      onSignal(JSON.parse(data.join('\n')) as RealtimeSignal)
      if (validId) sessionStorage.setItem(cursorKey, validId)
    } catch {
      // Keep the previous durable cursor so a malformed frame is not acknowledged.
    }
  }

  return { start, stop }
}

export function clearRealtimeCursor() {
  sessionStorage.removeItem(cursorKey)
}
