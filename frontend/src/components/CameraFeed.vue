<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import Hls from 'hls.js'
import { Camera, LoaderCircle, WifiOff } from 'lucide-vue-next'

const props = defineProps<{ url: string; status: string; code: string }>()
const video = ref<HTMLVideoElement | null>(null)
const state = ref<'idle' | 'loading' | 'playing' | 'error'>('idle')
const retryAttempt = ref(0)
let hls: Hls | null = null
let retryTimer: number | null = null
let waitingForOnline = false
let playbackWatchdog: number | null = null
let lastPlaybackTime: number | null = null
let stalledPlaybackChecks = 0

const statusLabel = computed(() => ({ online: '在线', degraded: '异常', offline: '离线', maintenance: '维护中' })[props.status] || props.status)

function cleanup() {
  if (retryTimer !== null) window.clearTimeout(retryTimer)
  retryTimer = null
  if (waitingForOnline) window.removeEventListener('online', reconnectAfterOnline)
  waitingForOnline = false
  hls?.destroy()
  hls = null
  lastPlaybackTime = null
  stalledPlaybackChecks = 0
  if (video.value) {
    video.value.pause()
    video.value.removeAttribute('src')
    video.value.load()
  }
}

function checkPlaybackProgress() {
  const element = video.value
  if (
    document.hidden
    || !element
    || props.status === 'offline'
    || state.value !== 'playing'
  ) {
    lastPlaybackTime = null
    stalledPlaybackChecks = 0
    return
  }
  if (element.ended) {
    scheduleRetry()
    return
  }
  if (element.paused) {
    element.play().catch(scheduleRetry)
    return
  }
  if (lastPlaybackTime !== null && Math.abs(element.currentTime - lastPlaybackTime) < 0.1) {
    stalledPlaybackChecks += 1
  } else {
    stalledPlaybackChecks = 0
  }
  lastPlaybackTime = element.currentTime
  if (stalledPlaybackChecks >= 2) scheduleRetry()
}

function scheduleRetry() {
  if (retryTimer !== null) return
  state.value = 'error'
  if (!navigator.onLine) {
    if (!waitingForOnline) {
      waitingForOnline = true
      window.addEventListener('online', reconnectAfterOnline, { once: true })
    }
    return
  }
  window.dispatchEvent(new Event('mineguard:media-session-needed'))
  const delay = Math.min(1000 * 2 ** Math.min(retryAttempt.value, 4), 15000) * (0.8 + Math.random() * 0.4)
  retryAttempt.value += 1
  retryTimer = window.setTimeout(connect, delay)
}

function reconnectAfterOnline() {
  waitingForOnline = false
  connect()
}

function connect() {
  cleanup()
  if (!video.value || props.status === 'offline' || !props.url) {
    state.value = 'idle'; return
  }
  if (!navigator.onLine) {
    scheduleRetry(); return
  }
  state.value = 'loading'
  if (video.value.canPlayType('application/vnd.apple.mpegurl')) {
    video.value.src = props.url
    video.value.play().catch(scheduleRetry)
    return
  }
  if (!Hls.isSupported()) {
    state.value = 'error'; return
  }
  hls = new Hls({
    lowLatencyMode: true,
    backBufferLength: 15,
    maxBufferLength: 10,
    manifestLoadingMaxRetry: 2,
    levelLoadingMaxRetry: 2,
  })
  hls.loadSource(props.url)
  hls.attachMedia(video.value)
  hls.on(Hls.Events.MANIFEST_PARSED, () => video.value?.play().catch(scheduleRetry))
  hls.on(Hls.Events.ERROR, (_, data) => {
    if (!data.fatal) return
    if (data.type === Hls.ErrorTypes.MEDIA_ERROR && retryAttempt.value < 2) {
      retryAttempt.value += 1; hls?.recoverMediaError()
    } else {
      scheduleRetry()
    }
  })
}

function markPlaying() { state.value = 'playing'; retryAttempt.value = 0 }
watch(() => [props.url, props.status], connect)
onMounted(() => {
  playbackWatchdog = window.setInterval(checkPlaybackProgress, 10_000)
  connect()
})
onBeforeUnmount(() => {
  if (playbackWatchdog !== null) window.clearInterval(playbackWatchdog)
  playbackWatchdog = null
  cleanup()
})
</script>

<template>
  <div class="camera-feed">
    <video ref="video" :aria-label="`${code} 实时监控画面`" muted autoplay playsinline @playing="markPlaying" @stalled="scheduleRetry" @error="scheduleRetry" />
    <div v-if="state !== 'playing'" class="feed-state">
      <WifiOff v-if="status === 'offline'" :size="29" />
      <LoaderCircle v-else-if="state === 'loading'" class="spin" :size="29" />
      <Camera v-else :size="29" />
      <span>{{ status === 'offline' ? '视频流中断' : state === 'error' ? '视频流重连中' : '正在连接视频流' }}</span>
    </div>
    <b :class="status"><i />{{ statusLabel }}</b>
    <small>{{ code }}</small>
  </div>
</template>

<style scoped>
.camera-feed { position: relative; overflow: hidden; display: grid; place-items: center; color: #4c5953; background-color: #0c100f; background-image: linear-gradient(rgba(42,52,47,.32) 1px, transparent 1px), linear-gradient(90deg, rgba(42,52,47,.32) 1px, transparent 1px); background-size: 24px 24px; }
video { position: absolute; inset: 0; width: 100%; height: 100%; object-fit: cover; background: #080b0a; }
.feed-state { position: relative; z-index: 1; display: grid; place-items: center; gap: 8px; }
.feed-state span { color: #637069; font-size: 10px; }
b { position: absolute; z-index: 2; top: 8px; right: 8px; padding: 4px 6px; display: flex; align-items: center; gap: 5px; color: #b4bdb8; background: rgba(8,11,10,.78); border-radius: 3px; font-size: 9px; font-weight: 500; }
b i { width: 6px; height: 6px; background: #8f9994; border-radius: 50%; }
b.online i { background: #31c48d; } b.degraded i { background: #f7ad4c; } b.offline i { background: #f05252; }
small { position: absolute; z-index: 2; left: 8px; top: 8px; color: #8b9690; font: 500 9px Consolas, monospace; }
.spin { animation: spin 1s linear infinite; } @keyframes spin { to { transform: rotate(360deg); } }
</style>
