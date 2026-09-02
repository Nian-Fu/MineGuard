<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import * as echarts from 'echarts'
import {
  Activity, AlertTriangle, Bell, BookOpen, BrainCircuit, Check, ChevronLeft, ChevronRight, GitBranch,
  CircleUserRound, Clock3, Cpu, Database, DoorOpen, Eye, Gauge, HardHat, KeyRound, LayoutDashboard,
  ListChecks, LoaderCircle, Lock, LogOut, Menu, PackageCheck, Pencil, Plus, Power, RefreshCw, ScanFace,
  ScrollText, Search, Settings, ShieldCheck, Siren, Upload, UserCog, UsersRound, Video, Wifi,
  Unlock, WifiOff, X,
} from 'lucide-vue-next'
import { api, apiEndpoint, clearAccessToken, refreshAccessToken, setAccessToken } from './api'
import CameraFeed from './components/CameraFeed.vue'
import { clearRealtimeCursor, createRealtimeClient } from './realtime'
import type { AlertRule, Algorithm, AuthenticationMethods, AuditLog, Camera, DashboardSummary, EdgeNode, EventItem, FaceTemplate, LlmConfiguration, ModelArtifact, NotificationDelivery, PageResponse, Person, RoleDefinition, User, VideoCaseManifest } from './types'

type View = 'dashboard' | 'cameras' | 'events' | 'persons' | 'algorithms' | 'video-cases' | 'rules' | 'administration' | 'system'
type Modal = 'camera' | 'camera-edit' | 'person' | 'person-edit' | 'person-status' | 'event-snapshot' | 'event-hold' | 'face-hold' | 'rule' | 'user' | 'user-access' | 'face' | 'password' | 'reset-password' | 'edge' | 'artifact' | 'artifact-approval' | null
type NotificationChannelId = 'console' | 'sms' | 'broadcast' | 'webhook'
const pendingLogoutKey = 'mineguard_pending_logout'

interface RuleDraft {
  name: string
  event_types: string[]
  minimum_severity: string
  areas: string[]
  channels: NotificationChannelId[]
  channel_targets: Record<string, string>
  cooldown_seconds: number
}

function emptyRuleDraft(): RuleDraft {
  return {
    name: '',
    event_types: ['intrusion'],
    minimum_severity: 'high',
    areas: [],
    channels: ['console'],
    channel_targets: {},
    cooldown_seconds: 60,
  }
}

function readStoredUser(): User | null {
  try {
    const value = JSON.parse(localStorage.getItem('mineguard_user') || 'null')
    if (!value || typeof value.username !== 'string' || typeof value.role !== 'string') return null
    return {
      ...value,
      identity_provider: value.identity_provider || 'local',
      permitted_areas: value.permitted_areas ?? null,
    } as User
  } catch {
    localStorage.removeItem('mineguard_user')
    clearAccessToken()
    return null
  }
}

const user = ref<User | null>(readStoredUser())
const username = ref('')
const password = ref('')
const loginError = ref('')
const loggingIn = ref(false)
const authMethods = ref<AuthenticationMethods>({
  local_enabled: true,
  oidc_enabled: false,
  oidc_provider_label: null,
})
const activeView = ref<View>('dashboard')
const loading = ref(false)
const liveRefreshing = ref(false)
const globalError = ref('')
const connectionState = ref<'online' | 'reconnecting' | 'offline'>(navigator.onLine ? 'online' : 'offline')
const reconnectAttempt = ref(0)
const sidebarOpen = ref(false)
const summary = ref<DashboardSummary | null>(null)
const cameras = ref<Camera[]>([])
const overviewCameras = ref<Camera[]>([])
const edgeCameraOptions = ref<Camera[]>([])
const events = ref<EventItem[]>([])
const persons = ref<Person[]>([])
const faceTemplates = ref<FaceTemplate[]>([])
const algorithms = ref<Algorithm[]>([])
const selectedAlgorithmId = ref<number | null>(null)
const videoCaseManifest = ref<VideoCaseManifest | null>(null)
const roleDefinitions = ref<RoleDefinition[]>([])
const llmConfiguration = ref<LlmConfiguration | null>(null)
const savingLlmConfiguration = ref(false)
const modelArtifacts = ref<ModelArtifact[]>([])
const alertRules = ref<AlertRule[]>([])
const auditLogs = ref<AuditLog[]>([])
const users = ref<User[]>([])
const deliveries = ref<NotificationDelivery[]>([])
const capabilities = ref<Record<string, string | number | boolean>>({})
const edgeNodes = ref<EdgeNode[]>([])
const pageSize = 50
const cameraPage = ref(1)
const cameraTotal = ref(0)
const eventPage = ref(1)
const eventTotal = ref(0)
const personPage = ref(1)
const personTotal = ref(0)
const deliveryPage = ref(1)
const deliveryTotal = ref(0)
const auditPage = ref(1)
const auditTotal = ref(0)
const faceTemplatePage = ref(1)
const faceTemplateTotal = ref(0)
const alertRulePage = ref(1)
const alertRuleTotal = ref(0)
const modelArtifactPage = ref(1)
const modelArtifactTotal = ref(0)
const userPage = ref(1)
const userTotal = ref(0)
const edgeNodePage = ref(1)
const edgeNodeTotal = ref(0)
const eventStatusFilter = ref('')
const search = ref('')
const modal = ref<Modal>(null)
const cameraForm = ref({ code: '', name: '', area: '', stream_url: '', enabled_algorithms: ['intrusion'] })
const selectedCamera = ref<Camera | null>(null)
const personForm = ref({ employee_no: '', name: '', department: '', person_type: 'employee', authorized_areas: [] as string[] })
const personAreasText = ref('')
const ruleForm = ref<RuleDraft>(emptyRuleDraft())
const ruleAreasText = ref('')
const selectedRule = ref<AlertRule | null>(null)
const userForm = ref({ username: '', full_name: '', password: '', role: 'operator', permitted_areas: [] as string[] | null })
const userAreasText = ref('')
const selectedPerson = ref<Person | null>(null)
const selectedEvent = ref<EventItem | null>(null)
const snapshotAccessUrl = ref('')
const snapshotLoading = ref(false)
const snapshotError = ref('')
const selectedFaceTemplate = ref<FaceTemplate | null>(null)
const legalHoldReason = ref('')
const pendingPersonActive = ref(false)
const faceConsentReference = ref('')
const faceImage = ref<File | null>(null)
const passwordForm = ref({ current_password: '', new_password: '' })
const selectedAccount = ref<User | null>(null)
const selectedAccountRole = ref('operator')
const resetPasswordValue = ref('')
const edgeForm = ref({ code: '', name: '', camera_ids: [] as number[] })
const issuedEdgeKey = ref('')
const selectedEdgeNode = ref<EdgeNode | null>(null)
const artifactForm = ref({ name: '', algorithm_type: 'object_detection', model_version: '', sha256: '', runtime: 'tensorrt-10', license_id: '', source_repository: '', source_commit: '', metrics: {} })
const artifactMetricsJson = ref('{}')
const selectedArtifact = ref<ModelArtifact | null>(null)
const artifactApproval = ref({ approved: true, reason: '' })
let trendChart: echarts.ECharts | null = null
let severityChart: echarts.ECharts | null = null
let liveRefreshTimer: number | null = null
let realtimeRefreshTimer: number | null = null
let mediaSessionTimer: number | null = null
let mediaSessionRenewal: Promise<void> | null = null
let lastMediaSessionRenewalAttempt = 0
let fullReloadPending = false
let pendingLogoutRequest: Promise<boolean> | null = null
let pendingLogoutRetryTimer: number | null = null
let pendingLogoutRetryAttempt = 0
let authMethodsRequest: Promise<void> | null = null
let authMethodsRetryTimer: number | null = null
let authMethodsRetryAttempt = 0
let snapshotRequestGeneration = 0
let cameraRequestGeneration = 0
let overviewCameraRequestGeneration = 0
let edgeCameraOptionsRequestGeneration = 0
let eventRequestGeneration = 0
let personRequestGeneration = 0
let deliveryRequestGeneration = 0
let auditRequestGeneration = 0
let faceTemplateRequestGeneration = 0
let alertRuleRequestGeneration = 0
let modelArtifactRequestGeneration = 0
let userRequestGeneration = 0
let edgeNodeRequestGeneration = 0
let searchReloadTimer: number | null = null
const realtimeClient = createRealtimeClient(scheduleRealtimeRefresh)

const navItems = computed(() => [
  { id: 'dashboard' as View, label: '生产总览', icon: LayoutDashboard },
  { id: 'cameras' as View, label: '监控点位', icon: Video },
  { id: 'events' as View, label: '事件中心', icon: Siren },
  { id: 'persons' as View, label: '人员库', icon: UsersRound },
  { id: 'algorithms' as View, label: '算法中心', icon: BrainCircuit },
  { id: 'video-cases' as View, label: '真实案例', icon: BookOpen },
  { id: 'rules' as View, label: '告警规则', icon: ListChecks },
  ...(user.value?.role === 'admin' || user.value?.role === 'auditor' ? [{ id: 'administration' as View, label: '管理与审计', icon: ScrollText }] : []),
  { id: 'system' as View, label: '系统状态', icon: Settings },
])
const titles: Record<View, [string, string]> = {
  dashboard: ['生产总览', '实时掌握矿井视频智能分析态势'], cameras: ['监控点位', '设备状态与算法能力编排'],
  events: ['事件中心', '告警研判、确认与闭环处置'], persons: ['人员库', '人员身份与区域授权管理'],
  algorithms: ['算法中心', '模型版本、阈值与部署状态'], 'video-cases': ['真实案例', '离线真实视频的算法基准记录'], system: ['系统状态', '服务健康与运行资源概览'],
  rules: ['告警规则', '事件分级、通知通道与抑制策略'], administration: ['管理与审计', '账号权限和操作记录追溯'],
}
const filteredEvents = computed(() => events.value.filter((event) => {
  const matchesStatus = !eventStatusFilter.value || event.status === eventStatusFilter.value
  const text = `${event.title}${event.camera.name}${event.camera.code}${event.camera.area}`.toLowerCase()
  return matchesStatus && text.includes(search.value.toLowerCase())
}))
const filteredPersons = computed(() => persons.value.filter((person) =>
  `${person.name}${person.employee_no}${person.department}`.toLowerCase().includes(search.value.toLowerCase()),
))

const typeLabels: Record<string, string> = {
  intrusion: '区域入侵', face_match: '人脸识别', unknown_face: '陌生人员', no_helmet: '未戴安全帽',
  crowding: '人员聚集', camera_offline: '设备离线',
}
const statusLabels: Record<string, string> = {
  online: '在线', offline: '离线', degraded: '异常', maintenance: '维护中', open: '待处置',
  acknowledged: '处理中', resolved: '已闭环', false_positive: '误报', ready: '已就绪', shadow: '影子运行',
  pending: '待投递', sent: '已送达', failed: '投递失败',
}
const severityLabels: Record<string, string> = { low: '低', medium: '中', high: '高', critical: '严重' }
const roleLabels: Record<string, string> = { admin: '系统管理员', operator: '值班员', auditor: '审计员' }
const ruleEventOptions = Object.entries(typeLabels).map(([value, label]) => ({ value, label }))
const notificationChannelOptions: Array<{ value: NotificationChannelId; label: string }> = [
  { value: 'console', label: '控制台' },
  { value: 'sms', label: '短信' },
  { value: 'broadcast', label: '广播' },
  { value: 'webhook', label: 'Webhook' },
]
const cameraAlgorithmOptions = computed(() => [...new Set([
  ...algorithms.value.map(algorithm => algorithm.algorithm_type),
  ...cameraForm.value.enabled_algorithms,
])])
const selectedAlgorithm = computed(() => algorithms.value.find(item => item.id === selectedAlgorithmId.value) || algorithms.value[0] || null)
const algorithmGuide = computed(() => {
  const algorithm = selectedAlgorithm.value
  if (!algorithm) return null
  const guides: Record<string, { summary: string; input: string; output: string; stages: string[]; notes: string[] }> = {
    object_detection: { summary: '从视频帧中定位人员、头部与安全帽候选框，并向规则层提交置信度和坐标。', input: '边缘节点解码后的 RGB 视频帧', output: '目标框、类别、置信度', stages: ['RTSP / HLS 帧解码', '尺度归一化与张量转换', 'Triton 目标检测推理', '置信度阈值过滤', '人员/头部/安全帽结果输出'], notes: ['阈值控制候选框过滤，不等同于人工标注精度。', '模型制品 SHA-256 必须与准入记录一致。'] },
    tracking: { summary: '为连续帧中的人员目标分配稳定轨迹，再将轨迹送入电子围栏、驻留和人数规则。', input: '人员检测框与时间戳', output: '轨迹 ID、位置、驻留时间、区域人数', stages: ['接收人员检测框', 'ByteTrack 关联', '轨迹生命周期维护', '电子围栏与驻留计算', '入侵/聚集事件判定'], notes: ['轨迹丢失或视频重连会重置关联状态。', '区域多摄像头人数以指定计数权威点位为准。'] },
    face_recognition: { summary: '在人脸授权和质量条件满足时，由受控 Provider 返回匹配结果，原始图像不在控制平台持久化。', input: '关联到人员轨迹的人脸裁剪', output: '匹配/未知状态、相似度、质量、活体结果', stages: ['人员轨迹关联', '人脸候选裁剪', '质量与活体检查', '加密模板匹配', '区域授权判断与事件输出'], notes: ['该流程需要独立启用的人脸 Provider 和加密模板密钥。', '低质量、多脸或活体失败会拒绝生成匹配。'] },
    rl_scheduler: { summary: '在安全约束下为推理资源分配任务，当前影子运行不会直接改变生产告警路径。', input: '队列、GPU、风险等级与约束状态', output: '建议优先级和调度决策', stages: ['收集节点遥测', '构建调度状态', '安全约束过滤', '策略决策', '影子结果记录'], notes: ['影子运行结果用于评估，不能替代已批准的生产策略。', '严重告警的最低采样频率受硬约束保护。'] },
  }
  return guides[algorithm.algorithm_type] || { summary: '该算法使用已登记的配置和模型制品执行受控处理。', input: '由边缘节点提供的受控输入', output: '算法配置定义的结构化结果', stages: ['输入校验', '模型或规则执行', '阈值判断', '结果上报'], notes: ['请结合下方 JSON 配置与模型制品记录审查。'] }
})

function concurrencyConfig(resource: { concurrency_token: string }) {
  return { headers: { 'If-Match': `"${resource.concurrency_token}"` } }
}

async function handleWriteError(error: any, fallback: string, closeOnConflict = false) {
  const detail = error.response?.data?.detail
  globalError.value = detail || fallback
  if (detail === '资源已被其他操作更新，请刷新后重新提交') {
    if (closeOnConflict) closeModal()
    await loadAll()
    globalError.value = detail
  }
}

const modalTitle = computed(() => {
  const labels: Record<Exclude<Modal, null>, string> = {
    camera: '新增监控点位', 'camera-edit': '编辑监控点位', person: '登记人员', 'person-edit': '编辑人员档案',
    'person-status': pendingPersonActive.value ? '启用人员档案' : '停用人员档案', 'event-snapshot': '事件快照', 'event-hold': selectedEvent.value?.legal_hold ? '解除事件法律保留' : '设置事件法律保留',
    'face-hold': selectedFaceTemplate.value?.legal_hold ? '解除模板法律保留' : '设置模板法律保留', rule: selectedRule.value ? '编辑告警规则' : '新增告警规则', user: '新增平台账号', 'user-access': '账号数据权限',
    password: '修改登录密码', 'reset-password': '重置账号密码', face: '登记人脸模板',
    edge: issuedEdgeKey.value ? '节点密钥已签发' : selectedEdgeNode.value ? '编辑边缘节点' : '注册边缘节点',
    artifact: '登记模型制品', 'artifact-approval': artifactApproval.value.approved ? '审批模型制品' : '撤销模型准入',
  }
  return modal.value ? labels[modal.value] : ''
})

const modalDescription = computed(() => {
  const labels: Record<Exclude<Modal, null>, string> = {
    camera: '录入设备与视频流信息', 'camera-edit': `更新 ${selectedCamera.value?.name || ''} 的点位配置`, person: '建立人员身份与区域授权档案',
    'person-edit': `更新 ${selectedPerson.value?.name || ''} 的身份与区域授权`, rule: selectedRule.value ? `更新 ${selectedRule.value.name} 的匹配与通知策略` : '配置事件通知与抑制策略',
    'person-status': `${selectedPerson.value?.employee_no || ''} · ${selectedPerson.value?.name || ''}`, 'event-snapshot': selectedEvent.value ? `${selectedEvent.value.camera.name} · ${formatTime(selectedEvent.value.occurred_at)}` : '', 'event-hold': selectedEvent.value?.title || '',
    'face-hold': selectedFaceTemplate.value ? `${selectedFaceTemplate.value.person?.name || `人员 #${selectedFaceTemplate.value.person_id}`} · 模板 #${selectedFaceTemplate.value.id}` : '',
    user: '分配账号、角色与最小生产区域范围', 'user-access': `调整 ${selectedAccount.value?.full_name || ''} 的角色与区域范围`, password: '修改后所有现有会话将立即失效',
    'reset-password': `重置 ${selectedAccount.value?.full_name || ''} 的登录凭据`,
    face: `为 ${selectedPerson.value?.name || ''} 加密登记生物特征`,
    edge: issuedEdgeKey.value ? `${selectedEdgeNode.value?.name || edgeForm.value.name} 的密钥只显示一次` : selectedEdgeNode.value ? '更新节点名称与允许处理的摄像头' : '分配摄像头并签发独立服务密钥',
    artifact: '锁定来源、许可证、提交版本与 SHA-256，审批前不可用于生产推理',
    'artifact-approval': `${selectedArtifact.value?.name || ''} · ${selectedArtifact.value?.model_version || ''}`,
  }
  return modal.value ? labels[modal.value] : ''
})

async function login() {
  loggingIn.value = true; loginError.value = ''
  try {
    if (!await flushPendingLogout()) throw new Error('pending logout could not be delivered')
    const { data } = await api.post('/auth/login', { username: username.value, password: password.value })
    setAccessToken(data.access_token)
    localStorage.setItem('mineguard_user', JSON.stringify(data.user))
    user.value = data.user
    await loadAll()
    realtimeClient.start()
  } catch (error: any) {
    loginError.value = error.response?.data?.detail || '无法连接监控平台'
  } finally { loggingIn.value = false }
}

function clearAuthenticationMethodsRetry() {
  if (authMethodsRetryTimer !== null) window.clearTimeout(authMethodsRetryTimer)
  authMethodsRetryTimer = null
  authMethodsRetryAttempt = 0
}

function scheduleAuthenticationMethodsRetry() {
  if (user.value || authMethodsRetryTimer !== null) return
  authMethodsRetryAttempt += 1
  const delay = Math.min(1000 * 2 ** (authMethodsRetryAttempt - 1), 30_000)
  authMethodsRetryTimer = window.setTimeout(() => {
    authMethodsRetryTimer = null
    if (!user.value) void loadAuthenticationMethods()
  }, delay + Math.random() * 350)
}

async function loadAuthenticationMethods(): Promise<void> {
  if (authMethodsRequest) return authMethodsRequest
  authMethodsRequest = (async () => {
    try {
      authMethods.value = (await api.get('/auth/methods')).data
      clearAuthenticationMethodsRetry()
    } catch {
      // Keep local login available while discovery retries in the background.
      scheduleAuthenticationMethodsRetry()
    } finally {
      authMethodsRequest = null
    }
  })()
  return authMethodsRequest
}

async function startOidcLogin() {
  loggingIn.value = true
  if (!await flushPendingLogout()) {
    loggingIn.value = false
    loginError.value = '网络尚未恢复，无法安全开始统一身份认证'
    return
  }
  window.location.assign(apiEndpoint('/auth/oidc/login'))
}

async function completeOidcLogin() {
  const callbackUrl = new URL(window.location.href)
  const failed = callbackUrl.searchParams.has('oidc_error')
  callbackUrl.pathname = callbackUrl.pathname.replace(/\/auth\/callback\/?$/, '/')
  callbackUrl.search = ''
  callbackUrl.hash = ''
  window.history.replaceState({}, '', `${callbackUrl.pathname}${callbackUrl.search}`)
  loggingIn.value = true
  try {
    if (failed) throw new Error('OIDC authentication failed')
    await refreshAccessToken()
    user.value = readStoredUser()
    await loadAll()
    realtimeClient.start()
  } catch {
    clearSession()
    loginError.value = '统一身份认证失败或登录已过期，请重试'
  } finally {
    loggingIn.value = false
  }
}

function clearSession() {
  realtimeClient.stop(); clearRealtimeCursor()
  fullReloadPending = false
  closeModal()
  cameraRequestGeneration += 1
  overviewCameraRequestGeneration += 1
  edgeCameraOptionsRequestGeneration += 1
  eventRequestGeneration += 1
  personRequestGeneration += 1
  deliveryRequestGeneration += 1
  auditRequestGeneration += 1
  faceTemplateRequestGeneration += 1
  alertRuleRequestGeneration += 1
  modelArtifactRequestGeneration += 1
  userRequestGeneration += 1
  edgeNodeRequestGeneration += 1
  clearAccessToken(); localStorage.removeItem('mineguard_user'); user.value = null
  activeView.value = 'dashboard'
  summary.value = null
  cameras.value = []
  overviewCameras.value = []
  edgeCameraOptions.value = []
  events.value = []
  persons.value = []
  faceTemplates.value = []
  algorithms.value = []
  videoCaseManifest.value = null
  roleDefinitions.value = []
  llmConfiguration.value = null
  modelArtifacts.value = []
  alertRules.value = []
  auditLogs.value = []
  users.value = []
  deliveries.value = []
  capabilities.value = {}
  edgeNodes.value = []
  cameraPage.value = 1; cameraTotal.value = 0
  eventPage.value = 1; eventTotal.value = 0
  personPage.value = 1; personTotal.value = 0
  deliveryPage.value = 1; deliveryTotal.value = 0
  auditPage.value = 1; auditTotal.value = 0
  faceTemplatePage.value = 1; faceTemplateTotal.value = 0
  alertRulePage.value = 1; alertRuleTotal.value = 0
  modelArtifactPage.value = 1; modelArtifactTotal.value = 0
  userPage.value = 1; userTotal.value = 0
  edgeNodePage.value = 1; edgeNodeTotal.value = 0
}

async function flushPendingLogout(): Promise<boolean> {
  if (localStorage.getItem(pendingLogoutKey) !== '1') return true
  if (!navigator.onLine) return false
  if (pendingLogoutRequest) return pendingLogoutRequest
  pendingLogoutRequest = api.post('/auth/logout')
    .then(() => {
      localStorage.removeItem(pendingLogoutKey)
      pendingLogoutRetryAttempt = 0
      if (pendingLogoutRetryTimer !== null) window.clearTimeout(pendingLogoutRetryTimer)
      pendingLogoutRetryTimer = null
      return true
    })
    .catch(() => {
      schedulePendingLogoutRetry()
      return false
    })
    .finally(() => { pendingLogoutRequest = null })
  return pendingLogoutRequest
}

function schedulePendingLogoutRetry() {
  if (pendingLogoutRetryTimer !== null || !navigator.onLine) return
  const exponent = Math.min(pendingLogoutRetryAttempt, 5)
  const delay = Math.min(1000 * 2 ** exponent, 30_000) * (0.8 + Math.random() * 0.4)
  pendingLogoutRetryAttempt += 1
  pendingLogoutRetryTimer = window.setTimeout(() => {
    pendingLogoutRetryTimer = null
    void flushPendingLogout()
  }, delay)
}

async function logout() {
  localStorage.setItem(pendingLogoutKey, '1')
  clearSession()
  await flushPendingLogout()
}

function totalPages(total: number): number {
  return Math.max(1, Math.ceil(total / pageSize))
}

async function loadCameraPage() {
  const generation = ++cameraRequestGeneration
  const query = activeView.value === 'cameras' ? search.value.trim() : ''
  const { data } = await api.get<PageResponse<Camera>>('/cameras', {
    params: { page: cameraPage.value, page_size: pageSize, query: query || undefined },
  })
  if (generation !== cameraRequestGeneration) return
  const lastPage = totalPages(data.total)
  if (cameraPage.value > lastPage) {
    cameraPage.value = lastPage
    await loadCameraPage()
    return
  }
  cameras.value = data.items
  cameraTotal.value = data.total
}

async function loadOverviewCameras() {
  const generation = ++overviewCameraRequestGeneration
  const { data } = await api.get<PageResponse<Camera>>('/cameras', {
    params: { page: 1, page_size: 4 },
  })
  if (generation !== overviewCameraRequestGeneration) return
  overviewCameras.value = data.items
}

async function loadEdgeCameraOptions(): Promise<boolean> {
  const generation = ++edgeCameraOptionsRequestGeneration
  const collected: Camera[] = []
  let page = 1
  let total = 0
  do {
    const { data } = await api.get<PageResponse<Camera>>('/cameras', {
      params: { page, page_size: 100 },
    })
    if (generation !== edgeCameraOptionsRequestGeneration) return false
    total = data.total
    if (total > 10_000) throw new Error('摄像头数量超过操作台绑定上限')
    if (!data.items.length && collected.length < total) {
      throw new Error('摄像头列表在加载期间发生变化，请重试')
    }
    collected.push(...data.items)
    page += 1
  } while (collected.length < total)
  edgeCameraOptions.value = collected
  return true
}

async function loadEventPage() {
  const generation = ++eventRequestGeneration
  const query = activeView.value === 'events' ? search.value.trim() : ''
  const { data } = await api.get<PageResponse<EventItem>>('/events', {
    params: {
      page: eventPage.value,
      page_size: pageSize,
      event_status: eventStatusFilter.value || undefined,
      query: query || undefined,
    },
  })
  if (generation !== eventRequestGeneration) return
  const lastPage = totalPages(data.total)
  if (eventPage.value > lastPage) {
    eventPage.value = lastPage
    await loadEventPage()
    return
  }
  events.value = data.items
  eventTotal.value = data.total
}

async function loadPersonPage() {
  const generation = ++personRequestGeneration
  const query = activeView.value === 'persons' ? search.value.trim() : ''
  const { data } = await api.get<PageResponse<Person>>('/persons', {
    params: { page: personPage.value, page_size: pageSize, query: query || undefined },
  })
  if (generation !== personRequestGeneration) return
  const lastPage = totalPages(data.total)
  if (personPage.value > lastPage) {
    personPage.value = lastPage
    await loadPersonPage()
    return
  }
  persons.value = data.items
  personTotal.value = data.total
}

async function loadDeliveryPage() {
  const generation = ++deliveryRequestGeneration
  const { data } = await api.get<PageResponse<NotificationDelivery>>('/notification-deliveries', {
    params: { page: deliveryPage.value, page_size: pageSize },
  })
  if (generation !== deliveryRequestGeneration) return
  const lastPage = totalPages(data.total)
  if (deliveryPage.value > lastPage) {
    deliveryPage.value = lastPage
    await loadDeliveryPage()
    return
  }
  deliveries.value = data.items
  deliveryTotal.value = data.total
}

async function loadAuditPage() {
  const generation = ++auditRequestGeneration
  const { data } = await api.get<PageResponse<AuditLog>>('/audit-logs', {
    params: { page: auditPage.value, page_size: pageSize },
  })
  if (generation !== auditRequestGeneration) return
  const lastPage = totalPages(data.total)
  if (auditPage.value > lastPage) {
    auditPage.value = lastPage
    await loadAuditPage()
    return
  }
  auditLogs.value = data.items
  auditTotal.value = data.total
}

async function loadFaceTemplatePage() {
  const generation = ++faceTemplateRequestGeneration
  const { data } = await api.get<PageResponse<FaceTemplate>>('/faces/templates', {
    params: { page: faceTemplatePage.value, page_size: pageSize },
  })
  if (generation !== faceTemplateRequestGeneration) return
  const lastPage = totalPages(data.total)
  if (faceTemplatePage.value > lastPage) {
    faceTemplatePage.value = lastPage
    await loadFaceTemplatePage()
    return
  }
  faceTemplates.value = data.items
  faceTemplateTotal.value = data.total
}

async function loadAlertRulePage() {
  const generation = ++alertRuleRequestGeneration
  const { data } = await api.get<PageResponse<AlertRule>>('/alert-rules/page', {
    params: { page: alertRulePage.value, page_size: pageSize },
  })
  if (generation !== alertRuleRequestGeneration) return
  const lastPage = totalPages(data.total)
  if (alertRulePage.value > lastPage) {
    alertRulePage.value = lastPage
    await loadAlertRulePage()
    return
  }
  alertRules.value = data.items
  alertRuleTotal.value = data.total
}

async function loadModelArtifactPage() {
  const generation = ++modelArtifactRequestGeneration
  const { data } = await api.get<PageResponse<ModelArtifact>>('/algorithms/artifacts/page', {
    params: { page: modelArtifactPage.value, page_size: pageSize },
  })
  if (generation !== modelArtifactRequestGeneration) return
  const lastPage = totalPages(data.total)
  if (modelArtifactPage.value > lastPage) {
    modelArtifactPage.value = lastPage
    await loadModelArtifactPage()
    return
  }
  modelArtifacts.value = data.items
  modelArtifactTotal.value = data.total
}

async function loadUserPage() {
  const generation = ++userRequestGeneration
  const { data } = await api.get<PageResponse<User>>('/users/page', {
    params: { page: userPage.value, page_size: pageSize },
  })
  if (generation !== userRequestGeneration) return
  const lastPage = totalPages(data.total)
  if (userPage.value > lastPage) {
    userPage.value = lastPage
    await loadUserPage()
    return
  }
  users.value = data.items
  userTotal.value = data.total
}

async function loadEdgeNodePage() {
  const generation = ++edgeNodeRequestGeneration
  const { data } = await api.get<PageResponse<EdgeNode>>('/edge-nodes/page', {
    params: { page: edgeNodePage.value, page_size: pageSize },
  })
  if (generation !== edgeNodeRequestGeneration) return
  const lastPage = totalPages(data.total)
  if (edgeNodePage.value > lastPage) {
    edgeNodePage.value = lastPage
    await loadEdgeNodePage()
    return
  }
  edgeNodes.value = data.items
  edgeNodeTotal.value = data.total
}

async function changePage(resource: 'cameras' | 'events' | 'persons' | 'deliveries' | 'audit' | 'face-templates' | 'alert-rules' | 'model-artifacts' | 'users' | 'edge-nodes', page: number) {
  if (resource === 'cameras') {
    cameraPage.value = Math.min(Math.max(page, 1), totalPages(cameraTotal.value))
    await loadCameraPage()
  } else if (resource === 'events') {
    eventPage.value = Math.min(Math.max(page, 1), totalPages(eventTotal.value))
    await loadEventPage()
  } else if (resource === 'persons') {
    personPage.value = Math.min(Math.max(page, 1), totalPages(personTotal.value))
    await loadPersonPage()
  } else if (resource === 'deliveries') {
    deliveryPage.value = Math.min(Math.max(page, 1), totalPages(deliveryTotal.value))
    await loadDeliveryPage()
  } else if (resource === 'audit') {
    auditPage.value = Math.min(Math.max(page, 1), totalPages(auditTotal.value))
    await loadAuditPage()
  } else if (resource === 'face-templates') {
    faceTemplatePage.value = Math.min(Math.max(page, 1), totalPages(faceTemplateTotal.value))
    await loadFaceTemplatePage()
  } else if (resource === 'alert-rules') {
    alertRulePage.value = Math.min(Math.max(page, 1), totalPages(alertRuleTotal.value))
    await loadAlertRulePage()
  } else if (resource === 'model-artifacts') {
    modelArtifactPage.value = Math.min(Math.max(page, 1), totalPages(modelArtifactTotal.value))
    await loadModelArtifactPage()
  } else if (resource === 'users') {
    userPage.value = Math.min(Math.max(page, 1), totalPages(userTotal.value))
    await loadUserPage()
  } else {
    edgeNodePage.value = Math.min(Math.max(page, 1), totalPages(edgeNodeTotal.value))
    await loadEdgeNodePage()
  }
}

async function reloadCurrentSearchView() {
  if (activeView.value === 'cameras') {
    cameraPage.value = 1
    await loadCameraPage()
  } else if (activeView.value === 'events') {
    eventPage.value = 1
    await loadEventPage()
  } else if (activeView.value === 'persons') {
    personPage.value = 1
    await loadPersonPage()
  }
}

async function loadAll() {
  if (loading.value) {
    fullReloadPending = true
    return
  }
  fullReloadPending = false
  loading.value = true; globalError.value = ''
  try {
    const [s, a, cap, videoCases] = await Promise.all([
      api.get('/dashboard/summary'), api.get('/algorithms'), api.get('/system/capabilities'),
      api.get('/video-cases'),
      loadCameraPage(), loadOverviewCameras(), loadEventPage(), loadPersonPage(), loadDeliveryPage(),
      loadAlertRulePage(), loadModelArtifactPage(), loadEdgeNodePage(),
    ])
    summary.value = s.data; algorithms.value = a.data
    capabilities.value = cap.data
    videoCaseManifest.value = videoCases.data
    if (user.value?.role === 'admin') {
      await loadUserPage()
      const [roles, llm] = await Promise.all([api.get('/roles'), api.get('/llm-configuration')])
      roleDefinitions.value = roles.data
      llmConfiguration.value = llm.data
    }
    else {
      users.value = []
      userTotal.value = 0
      roleDefinitions.value = []
      llmConfiguration.value = null
    }
    if (user.value?.role === 'admin' || user.value?.role === 'auditor') {
      await Promise.all([loadAuditPage(), loadFaceTemplatePage()])
    } else {
      auditLogs.value = []
      auditTotal.value = 0
      faceTemplates.value = []
      faceTemplateTotal.value = 0
    }
    if (activeView.value === 'dashboard') await renderCharts()
  } catch (error: any) {
    globalError.value = error.response?.data?.detail || '数据加载失败，请检查 API 服务'
  } finally {
    loading.value = false
    if (fullReloadPending && user.value && navigator.onLine) {
      fullReloadPending = false
      void loadAll()
    }
  }
}

async function renewMediaSession() {
  if (!user.value || !navigator.onLine) return
  if (mediaSessionRenewal) return mediaSessionRenewal
  const now = Date.now()
  if (now - lastMediaSessionRenewalAttempt < 15_000) return
  lastMediaSessionRenewalAttempt = now
  mediaSessionRenewal = api.post('/auth/media-session')
    .then(() => undefined)
    .catch(() => undefined)
    .finally(() => { mediaSessionRenewal = null })
  return mediaSessionRenewal
}

function recoverMediaSession() { void renewMediaSession() }

async function updateEvent(event: EventItem, status: 'acknowledged' | 'resolved' | 'false_positive') {
  try {
    const { data } = await api.patch(`/events/${event.id}/status`, { status, note: '操作台人工处置' }, concurrencyConfig(event))
    const index = events.value.findIndex((item) => item.id === event.id)
    if (index >= 0) events.value[index] = data
    await refreshSummary()
  } catch (error: any) { await handleWriteError(error, '事件处置失败') }
}

function openEventLegalHold(event: EventItem) {
  selectedEvent.value = event
  legalHoldReason.value = ''
  modal.value = 'event-hold'
}

async function loadEventSnapshot() {
  if (!selectedEvent.value) return
  const eventId = selectedEvent.value.id
  const generation = ++snapshotRequestGeneration
  snapshotLoading.value = true
  snapshotError.value = ''
  snapshotAccessUrl.value = ''
  try {
    const { data } = await api.get(`/events/${eventId}/snapshot-access`)
    if (generation !== snapshotRequestGeneration || modal.value !== 'event-snapshot') return
    snapshotAccessUrl.value = data.download_url
  } catch (error: any) {
    if (generation !== snapshotRequestGeneration || modal.value !== 'event-snapshot') return
    snapshotError.value = error.response?.data?.detail || '快照暂时无法加载'
  } finally {
    if (generation === snapshotRequestGeneration) snapshotLoading.value = false
  }
}

function openEventSnapshot(event: EventItem) {
  selectedEvent.value = event
  modal.value = 'event-snapshot'
  void loadEventSnapshot()
}

function handleSnapshotLoadError() {
  snapshotAccessUrl.value = ''
  snapshotError.value = navigator.onLine ? '快照对象暂时无法读取' : '网络已断开，恢复后请重新加载'
}

async function setEventLegalHold() {
  if (!selectedEvent.value) return
  try {
    const { data } = await api.patch(`/events/${selectedEvent.value.id}/legal-hold`, {
      enabled: !selectedEvent.value.legal_hold,
      reason: legalHoldReason.value.trim(),
    }, concurrencyConfig(selectedEvent.value))
    Object.assign(selectedEvent.value, data)
    closeModal()
  } catch (error: any) {
    await handleWriteError(error, '事件法律保留状态修改失败', true)
  }
}

async function toggleAlgorithm(algorithm: Algorithm) {
  try {
    const { data } = await api.patch(`/algorithms/${algorithm.id}`, { enabled: !algorithm.enabled }, concurrencyConfig(algorithm))
    Object.assign(algorithm, data)
  } catch (error: any) { await handleWriteError(error, '只有管理员可以修改算法配置') }
}

async function updateAlgorithmThreshold(algorithm: Algorithm, event: Event) {
  const threshold = Number((event.target as HTMLInputElement).value)
  try { Object.assign(algorithm, (await api.patch(`/algorithms/${algorithm.id}`, { threshold }, concurrencyConfig(algorithm))).data) }
  catch (error: any) {
    await handleWriteError(error, '算法阈值修改失败')
  }
}

function openCameraCreation() {
  selectedCamera.value = null
  cameraForm.value = { code: '', name: '', area: '', stream_url: '', enabled_algorithms: ['intrusion'] }
  modal.value = 'camera'
}

function openCameraEdit(camera: Camera) {
  selectedCamera.value = camera
  cameraForm.value = {
    code: camera.code,
    name: camera.name,
    area: camera.area,
    stream_url: '',
    enabled_algorithms: [...camera.enabled_algorithms],
  }
  modal.value = 'camera-edit'
}

async function saveCamera() {
  try {
    if (selectedCamera.value) {
      const payload: Record<string, unknown> = {
        name: cameraForm.value.name,
        area: cameraForm.value.area,
        enabled_algorithms: cameraForm.value.enabled_algorithms,
      }
      if (cameraForm.value.stream_url.trim()) payload.stream_url = cameraForm.value.stream_url.trim()
      const { data } = await api.patch(`/cameras/${selectedCamera.value.id}`, payload, concurrencyConfig(selectedCamera.value))
      Object.assign(selectedCamera.value, data)
      closeModal()
    } else {
      await api.post('/cameras', cameraForm.value)
      await loadCameraPage()
      closeModal()
    }
  } catch (error: any) { await handleWriteError(error, selectedCamera.value ? '监控点位更新失败' : '新增摄像头失败', Boolean(selectedCamera.value)) }
}

async function createPerson() {
  try {
    personForm.value.authorized_areas = parseAreas(personAreasText.value)
    await api.post('/persons', personForm.value); modal.value = null
    personForm.value = { employee_no: '', name: '', department: '', person_type: 'employee', authorized_areas: [] }
    personAreasText.value = ''
    await loadAll()
  } catch (error: any) { globalError.value = error.response?.data?.detail || '新增人员失败' }
}

function parseAreas(value: string): string[] {
  return [...new Set(value.split(/[,，]/).map(area => area.trim()).filter(Boolean))]
}

function openPersonCreation() {
  selectedPerson.value = null
  selectedEvent.value = null
  legalHoldReason.value = ''
  personForm.value = { employee_no: '', name: '', department: '', person_type: 'employee', authorized_areas: [] }
  personAreasText.value = ''
  modal.value = 'person'
}

function openPersonEdit(person: Person) {
  selectedPerson.value = person
  personForm.value = {
    employee_no: person.employee_no,
    name: person.name,
    department: person.department,
    person_type: person.person_type,
    authorized_areas: [...person.authorized_areas],
  }
  personAreasText.value = person.authorized_areas.join('，')
  modal.value = 'person-edit'
}

async function updatePersonProfile() {
  if (!selectedPerson.value) return
  try {
    const { data } = await api.patch(`/persons/${selectedPerson.value.id}`, {
      name: personForm.value.name,
      department: personForm.value.department,
      person_type: personForm.value.person_type,
      authorized_areas: parseAreas(personAreasText.value),
    }, concurrencyConfig(selectedPerson.value))
    Object.assign(selectedPerson.value, data); closeModal()
  } catch (error: any) { await handleWriteError(error, '人员档案更新失败', true) }
}

function openPersonStatus(person: Person) {
  selectedPerson.value = person
  pendingPersonActive.value = !person.active
  modal.value = 'person-status'
}

async function setPersonActive() {
  if (!selectedPerson.value) return
  try {
    Object.assign(selectedPerson.value, (await api.patch(`/persons/${selectedPerson.value.id}`, { active: pendingPersonActive.value }, concurrencyConfig(selectedPerson.value))).data)
    closeModal()
  } catch (error: any) { await handleWriteError(error, '人员状态修改失败', true) }
}

async function saveRule() {
  if (!ruleForm.value.event_types.length || !ruleForm.value.channels.length) {
    globalError.value = '至少选择一种事件类型和一个通知通道'
    return
  }
  try {
    const channel_targets = Object.fromEntries(
      ruleForm.value.channels
        .filter(channel => channel !== 'console' && ruleForm.value.channel_targets[channel]?.trim())
        .map(channel => [channel, ruleForm.value.channel_targets[channel].trim()]),
    )
    const payload = {
      ...ruleForm.value,
      areas: parseAreas(ruleAreasText.value),
      channel_targets,
    }
    if (selectedRule.value) {
      const { data } = await api.patch(`/alert-rules/${selectedRule.value.id}`, payload, concurrencyConfig(selectedRule.value))
      Object.assign(selectedRule.value, data)
    } else {
      await api.post('/alert-rules', payload)
      alertRulePage.value = totalPages(alertRuleTotal.value + 1)
      await loadAlertRulePage()
    }
    closeModal()
  } catch (error: any) { await handleWriteError(error, selectedRule.value ? '告警规则更新失败' : '新增告警规则失败', Boolean(selectedRule.value)) }
}

function openRuleCreation() {
  selectedRule.value = null
  ruleForm.value = emptyRuleDraft()
  ruleAreasText.value = ''
  modal.value = 'rule'
}

function openRuleEdit(rule: AlertRule) {
  selectedRule.value = rule
  ruleForm.value = {
    name: rule.name,
    event_types: [...rule.event_types],
    minimum_severity: rule.minimum_severity,
    areas: [...rule.areas],
    channels: rule.channels.filter((channel): channel is NotificationChannelId =>
      notificationChannelOptions.some(option => option.value === channel),
    ),
    channel_targets: { ...rule.channel_targets },
    cooldown_seconds: rule.cooldown_seconds,
  }
  ruleAreasText.value = rule.areas.join('，')
  modal.value = 'rule'
}

async function toggleRule(rule: AlertRule) {
  try { Object.assign(rule, (await api.patch(`/alert-rules/${rule.id}`, { enabled: !rule.enabled }, concurrencyConfig(rule))).data) }
  catch (error: any) { await handleWriteError(error, '只有管理员可以修改规则') }
}

async function createUser() {
  try {
    userForm.value.permitted_areas = userForm.value.role === 'admin' ? null : parseAreas(userAreasText.value)
    await api.post('/users', userForm.value); modal.value = null
    userForm.value = { username: '', full_name: '', password: '', role: 'operator', permitted_areas: [] }
    userAreasText.value = ''
    await loadUserPage()
  } catch (error: any) {
    const detail = error.response?.data?.detail
    globalError.value = Array.isArray(detail) ? detail[0]?.msg : detail || '新增账号失败'
  }
}

function openUserCreation() {
  userForm.value = {
    username: '', full_name: '', password: '', role: 'operator', permitted_areas: [],
  }
  userAreasText.value = ''
  modal.value = 'user'
}

function openFaceEnrollment(person: Person) {
  selectedPerson.value = person; faceConsentReference.value = ''; faceImage.value = null; modal.value = 'face'
}

function chooseFaceImage(event: Event) {
  faceImage.value = (event.target as HTMLInputElement).files?.[0] || null
}

async function enrollFace() {
  if (!selectedPerson.value || !faceImage.value) {
    globalError.value = '请选择一张登记图像'; return
  }
  const form = new FormData()
  form.append('image', faceImage.value)
  form.append('consent_reference', faceConsentReference.value)
  try {
    await api.post(`/faces/enroll/${selectedPerson.value.id}`, form)
    closeModal(); await loadAll()
  } catch (error: any) { globalError.value = error.response?.data?.detail || '人脸登记失败' }
}

function edgeOutboxUtilization(node: EdgeNode): number {
  const depth = Number(node.telemetry.queue_depth || 0) + Number(node.telemetry.dead_letter_depth || 0)
  return depth / Math.max(Number(node.telemetry.outbox_capacity || 100_000), 1)
}

async function saveLlmConfiguration() {
  if (!llmConfiguration.value) return
  savingLlmConfiguration.value = true
  try {
    const { data } = await api.patch('/llm-configuration', {
      enabled: llmConfiguration.value.enabled,
      provider: llmConfiguration.value.provider,
      base_url: llmConfiguration.value.base_url.trim(),
      model: llmConfiguration.value.model.trim(),
      api_key_env: llmConfiguration.value.api_key_env.trim(),
      temperature: Number(llmConfiguration.value.temperature),
      max_tokens: Number(llmConfiguration.value.max_tokens),
      system_prompt: llmConfiguration.value.system_prompt.trim(),
    }, concurrencyConfig(llmConfiguration.value))
    llmConfiguration.value = data
  } catch (error: any) {
    await handleWriteError(error, '大模型配置保存失败')
  } finally {
    savingLlmConfiguration.value = false
  }
}

async function revokeFaceTemplate(template: FaceTemplate) {
  const identity = template.person ? `${template.person.name} · ${template.person.employee_no}` : `人员 #${template.person_id}`
  if (!window.confirm(`确认吊销 ${identity} 的人脸模板 #${template.id}？`)) return
  try {
    await api.delete(`/faces/templates/${template.id}`, concurrencyConfig(template))
    await loadAll()
  } catch (error: any) { await handleWriteError(error, '人脸模板吊销失败') }
}

function openFaceTemplateLegalHold(template: FaceTemplate) {
  selectedFaceTemplate.value = template
  legalHoldReason.value = ''
  modal.value = 'face-hold'
}

async function setFaceTemplateLegalHold() {
  if (!selectedFaceTemplate.value) return
  try {
    const { data } = await api.patch(`/faces/templates/${selectedFaceTemplate.value.id}/legal-hold`, {
      enabled: !selectedFaceTemplate.value.legal_hold,
      reason: legalHoldReason.value.trim(),
    }, concurrencyConfig(selectedFaceTemplate.value))
    Object.assign(selectedFaceTemplate.value, data)
    closeModal()
  } catch (error: any) { await handleWriteError(error, '人脸模板法律保留状态修改失败', true) }
}

async function retryDelivery(delivery: NotificationDelivery) {
  try { Object.assign(delivery, (await api.post(`/notification-deliveries/${delivery.id}/retry`)).data) }
  catch (error: any) { globalError.value = error.response?.data?.detail || '通知重试失败' }
}

async function changePassword() {
  try {
    await api.post('/auth/change-password', passwordForm.value)
    passwordForm.value = { current_password: '', new_password: '' }
    closeModal(); clearSession(); loginError.value = '密码已修改，请使用新密码重新登录'
  } catch (error: any) {
    const detail = error.response?.data?.detail
    globalError.value = Array.isArray(detail) ? detail[0]?.msg : detail || '密码修改失败'
  }
}

async function toggleAccount(account: User) {
  try { Object.assign(account, (await api.patch(`/users/${account.id}`, { active: !account.active }, concurrencyConfig(account))).data) }
  catch (error: any) { await handleWriteError(error, '账号状态修改失败') }
}

function openAccountAccess(account: User, role = account.role) {
  selectedAccount.value = account
  selectedAccountRole.value = role
  userAreasText.value = (account.permitted_areas || []).join('，')
  modal.value = 'user-access'
}

function accountScopeLabel(account: User) {
  if (account.role === 'admin' || account.permitted_areas === null) return '全部生产区域'
  return account.permitted_areas.length ? account.permitted_areas.join('、') : '未分配区域'
}

function updateAccountRole(account: User, event: Event) {
  const select = event.target as HTMLSelectElement
  const requestedRole = select.value
  select.value = account.role
  openAccountAccess(account, requestedRole)
}

async function saveAccountAccess() {
  if (!selectedAccount.value) return
  try {
    const { data } = await api.patch(`/users/${selectedAccount.value.id}`, {
      role: selectedAccountRole.value,
      permitted_areas: selectedAccountRole.value === 'admin' ? null : parseAreas(userAreasText.value),
    }, concurrencyConfig(selectedAccount.value))
    Object.assign(selectedAccount.value, data)
    closeModal()
  } catch (error: any) {
    await handleWriteError(error, '账号数据权限修改失败', true)
  }
}

function openPasswordReset(account: User) {
  selectedAccount.value = account; resetPasswordValue.value = ''; modal.value = 'reset-password'
}

async function resetAccountPassword() {
  if (!selectedAccount.value) return
  try {
    await api.post(`/users/${selectedAccount.value.id}/reset-password`, { new_password: resetPasswordValue.value }, concurrencyConfig(selectedAccount.value))
    closeModal(); resetPasswordValue.value = ''; await loadAll()
  } catch (error: any) {
    const detail = error.response?.data?.detail
    if (detail === '资源已被其他操作更新，请刷新后重新提交') {
      await handleWriteError(error, '密码重置失败', true)
    } else {
      globalError.value = Array.isArray(detail) ? detail[0]?.msg : detail || '密码重置失败'
    }
  }
}

async function openEdgeRegistration() {
  try {
    if (!await loadEdgeCameraOptions()) return
    edgeForm.value = { code: '', name: '', camera_ids: [] }; issuedEdgeKey.value = ''; selectedEdgeNode.value = null; modal.value = 'edge'
  } catch (error: any) {
    globalError.value = error.response?.data?.detail || error.message || '摄像头绑定候选加载失败'
  }
}

async function openEdgeEdit(node: EdgeNode) {
  try {
    if (!await loadEdgeCameraOptions()) return
    selectedEdgeNode.value = node
    issuedEdgeKey.value = ''
    edgeForm.value = {
      code: node.code,
      name: node.name,
      camera_ids: [...node.camera_ids],
    }
    modal.value = 'edge'
  } catch (error: any) {
    globalError.value = error.response?.data?.detail || error.message || '摄像头绑定候选加载失败'
  }
}

function closeModal() {
  snapshotRequestGeneration += 1
  modal.value = null
  issuedEdgeKey.value = ''
  selectedRule.value = null
  selectedCamera.value = null
  selectedAccount.value = null
  selectedPerson.value = null
  selectedEvent.value = null
  snapshotAccessUrl.value = ''
  snapshotLoading.value = false
  snapshotError.value = ''
  selectedFaceTemplate.value = null
  selectedEdgeNode.value = null
  selectedArtifact.value = null
  legalHoldReason.value = ''
  ruleForm.value = emptyRuleDraft()
  ruleAreasText.value = ''
  faceImage.value = null
}

async function saveEdgeNode() {
  try {
    if (selectedEdgeNode.value) {
      const { data } = await api.patch(`/edge-nodes/${selectedEdgeNode.value.id}`, {
        name: edgeForm.value.name,
        camera_ids: edgeForm.value.camera_ids,
      }, concurrencyConfig(selectedEdgeNode.value))
      Object.assign(selectedEdgeNode.value, data)
      closeModal()
      return
    }
    const { data } = await api.post('/edge-nodes', edgeForm.value)
    issuedEdgeKey.value = data.api_key
    selectedEdgeNode.value = data.node
    edgeNodePage.value = totalPages(edgeNodeTotal.value + 1)
    await loadEdgeNodePage()
  } catch (error: any) {
    await handleWriteError(error, selectedEdgeNode.value ? '边缘节点更新失败' : '边缘节点注册失败', Boolean(selectedEdgeNode.value))
  }
}

async function rotateEdgeKey(node: EdgeNode) {
  try {
    const { data } = await api.post(`/edge-nodes/${node.id}/rotate-key`, undefined, concurrencyConfig(node))
    Object.assign(node, data.node); selectedEdgeNode.value = node; issuedEdgeKey.value = data.api_key; modal.value = 'edge'
  } catch (error: any) { await handleWriteError(error, '边缘节点密钥轮换失败') }
}

async function setEdgeNodeActive(node: EdgeNode) {
  if (node.active && !window.confirm(`确认停用边缘节点 ${node.name}？其服务密钥将立即失效。`)) return
  try {
    Object.assign(node, (await api.patch(`/edge-nodes/${node.id}`, { active: !node.active }, concurrencyConfig(node))).data)
  } catch (error: any) { await handleWriteError(error, '边缘节点状态修改失败') }
}

function openArtifactCreation() {
  artifactForm.value = { name: '', algorithm_type: 'object_detection', model_version: '', sha256: '', runtime: 'tensorrt-10', license_id: '', source_repository: '', source_commit: '', metrics: {} }
  artifactMetricsJson.value = '{}'
  modal.value = 'artifact'
}

async function createArtifact() {
  try {
    const parsedMetrics = JSON.parse(artifactMetricsJson.value)
    if (!parsedMetrics || Array.isArray(parsedMetrics) || typeof parsedMetrics !== 'object') throw new Error('invalid metrics')
    artifactForm.value.metrics = parsedMetrics
    await api.post('/algorithms/artifacts', artifactForm.value)
    modelArtifactPage.value = 1
    await loadModelArtifactPage()
    closeModal()
  } catch (error: any) {
    if (error instanceof SyntaxError || error.message === 'invalid metrics') {
      globalError.value = '评估指标必须是 JSON 对象'; return
    }
    const detail = error.response?.data?.detail
    globalError.value = Array.isArray(detail) ? detail[0]?.msg : detail || '模型制品登记失败'
  }
}

function openArtifactApproval(artifact: ModelArtifact, approved: boolean) {
  selectedArtifact.value = artifact; artifactApproval.value = { approved, reason: '' }; modal.value = 'artifact-approval'
}

async function approveArtifact() {
  if (!selectedArtifact.value) return
  try {
    const { data } = await api.post(`/algorithms/artifacts/${selectedArtifact.value.id}/approval`, artifactApproval.value, concurrencyConfig(selectedArtifact.value))
    Object.assign(selectedArtifact.value, data); closeModal()
  } catch (error: any) { await handleWriteError(error, '模型审批失败', true) }
}

function submitModal() {
  if (modal.value === 'camera' || modal.value === 'camera-edit') return saveCamera()
  if (modal.value === 'person') return createPerson()
  if (modal.value === 'person-edit') return updatePersonProfile()
  if (modal.value === 'person-status') return setPersonActive()
  if (modal.value === 'event-hold') return setEventLegalHold()
  if (modal.value === 'face-hold') return setFaceTemplateLegalHold()
  if (modal.value === 'rule') return saveRule()
  if (modal.value === 'user') return createUser()
  if (modal.value === 'user-access') return saveAccountAccess()
  if (modal.value === 'face') return enrollFace()
  if (modal.value === 'password') return changePassword()
  if (modal.value === 'reset-password') return resetAccountPassword()
  if (modal.value === 'edge') return saveEdgeNode()
  if (modal.value === 'artifact') return createArtifact()
  if (modal.value === 'artifact-approval') return approveArtifact()
}

async function refreshSummary() {
  const { data } = await api.get('/dashboard/summary'); summary.value = data
}

async function refreshLiveData() {
  if (!user.value || !navigator.onLine || liveRefreshing.value) return
  liveRefreshing.value = true
  try {
    const [s] = await Promise.all([
      api.get('/dashboard/summary'), loadCameraPage(), loadOverviewCameras(), loadEventPage(), loadDeliveryPage(),
    ])
    summary.value = s.data
  } catch {
    // The API interceptor owns retry and connection-state reporting.
  } finally { liveRefreshing.value = false }
}

function scheduleRealtimeRefresh() {
  if (realtimeRefreshTimer !== null) return
  realtimeRefreshTimer = window.setTimeout(() => {
    realtimeRefreshTimer = null
    void refreshLiveData()
  }, 250)
}

async function selectView(view: View) {
  activeView.value = view; sidebarOpen.value = false; search.value = ''
  if (view === 'dashboard') await renderCharts()
  else if (view === 'cameras') await loadCameraPage()
  else if (view === 'events') await loadEventPage()
  else if (view === 'persons') {
    const requests = [loadPersonPage()]
    if (user.value?.role === 'admin' || user.value?.role === 'auditor') requests.push(loadFaceTemplatePage())
    await Promise.all(requests)
  } else if (view === 'algorithms') await loadModelArtifactPage()
  else if (view === 'rules') await Promise.all([loadAlertRulePage(), loadDeliveryPage()])
  else if (view === 'administration' && (user.value?.role === 'admin' || user.value?.role === 'auditor')) {
    const requests = [loadAuditPage()]
    if (user.value.role === 'admin') requests.push(loadUserPage())
    await Promise.all(requests)
  } else if (view === 'system') await loadEdgeNodePage()
}

async function renderCharts() {
  await nextTick()
  if (!summary.value) return
  const trendEl = document.getElementById('trend-chart')
  const severityEl = document.getElementById('severity-chart')
  if (trendEl) {
    trendChart?.dispose(); trendChart = echarts.init(trendEl)
    trendChart.setOption({
      grid: { left: 30, right: 14, top: 18, bottom: 24 }, tooltip: { trigger: 'axis' },
      xAxis: { type: 'category', data: summary.value.hourly_trend.map(x => x.time), axisLine: { lineStyle: { color: '#45504b' } }, axisLabel: { color: '#87918c', interval: 1 } },
      yAxis: { type: 'value', minInterval: 1, splitLine: { lineStyle: { color: '#27302c' } }, axisLabel: { color: '#87918c' } },
      series: [{ data: summary.value.hourly_trend.map(x => x.count), type: 'line', smooth: true, symbol: 'none', lineStyle: { color: '#31c48d', width: 3 }, areaStyle: { color: 'rgba(49,196,141,.12)' } }],
    })
  }
  if (severityEl) {
    severityChart?.dispose(); severityChart = echarts.init(severityEl)
    const colors: Record<string, string> = { critical: '#f05252', high: '#ff9f43', medium: '#faca15', low: '#4ca3ff' }
    severityChart.setOption({
      tooltip: { trigger: 'item' }, legend: { bottom: 0, textStyle: { color: '#a7b0ac' } },
      series: [{ type: 'pie', radius: ['54%', '76%'], center: ['50%', '44%'], label: { show: false }, data: Object.entries(summary.value.severity_distribution).map(([name, value]) => ({ name: severityLabels[name], value, itemStyle: { color: colors[name] } })) }],
    })
  }
}

function formatTime(value: string | null) {
  if (!value) return '--'
  return new Intl.DateTimeFormat('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false }).format(new Date(value))
}
function resizeCharts() { trendChart?.resize(); severityChart?.resize() }
function markOnline() {
  connectionState.value = 'online'; reconnectAttempt.value = 0
  pendingLogoutRetryAttempt = 0
  void flushPendingLogout()
  if (user.value) {
    void renewMediaSession()
    void loadAll()
  } else {
    clearAuthenticationMethodsRetry()
    void loadAuthenticationMethods()
  }
}
function markConnected() {
  const recovered = connectionState.value !== 'online'
  connectionState.value = 'online'; reconnectAttempt.value = 0
  if (recovered && user.value) {
    void renewMediaSession()
    void loadAll()
  }
}
function markOffline() { connectionState.value = 'offline' }
function markReconnecting(event: Event) {
  connectionState.value = 'reconnecting'
  reconnectAttempt.value = (event as CustomEvent<number>).detail || 1
}

watch(summary, () => { if (activeView.value === 'dashboard') renderCharts() })
watch(user, (currentUser) => { if (currentUser) clearAuthenticationMethodsRetry() })
watch(search, () => {
  if (searchReloadTimer !== null) window.clearTimeout(searchReloadTimer)
  if (!['cameras', 'events', 'persons'].includes(activeView.value)) return
  searchReloadTimer = window.setTimeout(() => {
    searchReloadTimer = null
    void reloadCurrentSearchView()
  }, 300)
})
watch(eventStatusFilter, () => {
  eventPage.value = 1
  if (activeView.value === 'events') void loadEventPage()
})
onMounted(async () => {
  window.addEventListener('mineguard:unauthorized', clearSession); window.addEventListener('resize', resizeCharts)
  window.addEventListener('mineguard:reconnecting', markReconnecting)
  window.addEventListener('mineguard:connection-lost', markOffline)
  window.addEventListener('mineguard:connection-restored', markConnected)
  window.addEventListener('mineguard:media-session-needed', recoverMediaSession)
  window.addEventListener('online', markOnline); window.addEventListener('offline', markOffline)
  await flushPendingLogout()
  await loadAuthenticationMethods()
  if (window.location.pathname.replace(/\/$/, '').endsWith('/auth/callback')) {
    await completeOidcLogin()
  } else if (user.value) {
    await loadAll()
    await renewMediaSession()
    realtimeClient.start()
  }
  liveRefreshTimer = window.setInterval(refreshLiveData, 20_000)
  mediaSessionTimer = window.setInterval(renewMediaSession, 5 * 60_000)
})
onBeforeUnmount(() => {
  window.removeEventListener('mineguard:unauthorized', clearSession); window.removeEventListener('resize', resizeCharts)
  window.removeEventListener('mineguard:reconnecting', markReconnecting)
  window.removeEventListener('mineguard:connection-lost', markOffline)
  window.removeEventListener('mineguard:connection-restored', markConnected)
  window.removeEventListener('mineguard:media-session-needed', recoverMediaSession)
  window.removeEventListener('online', markOnline); window.removeEventListener('offline', markOffline)
  if (liveRefreshTimer !== null) window.clearInterval(liveRefreshTimer)
  if (mediaSessionTimer !== null) window.clearInterval(mediaSessionTimer)
  if (realtimeRefreshTimer !== null) window.clearTimeout(realtimeRefreshTimer)
  if (pendingLogoutRetryTimer !== null) window.clearTimeout(pendingLogoutRetryTimer)
  if (searchReloadTimer !== null) window.clearTimeout(searchReloadTimer)
  clearAuthenticationMethodsRetry()
  realtimeClient.stop()
  trendChart?.dispose(); severityChart?.dispose()
})
</script>

<template>
  <main v-if="!user" class="login-shell">
    <section class="login-brand">
      <div class="brand-mark large"><HardHat :size="30" /></div>
      <div><strong>MineGuard AI</strong><span>矿井生产智能监控平台</span></div>
      <div class="signal-field" aria-hidden="true"><i v-for="n in 24" :key="n" /></div>
      <div class="brand-statement"><ShieldCheck :size="24" /><p>统一感知 · 风险研判 · 闭环处置</p></div>
    </section>
    <section class="login-panel">
      <form class="login-form" @submit.prevent="login">
        <p class="eyebrow">AUTHORIZED ACCESS</p>
        <h1>登录生产控制台</h1>
        <p class="muted">使用已分配的生产身份继续</p>
        <template v-if="authMethods.local_enabled">
          <label>用户名<input v-model="username" autocomplete="username" required /></label>
          <label>密码<input v-model="password" type="password" autocomplete="current-password" required minlength="8" /></label>
        </template>
        <p v-if="loginError" class="form-error"><AlertTriangle :size="16" />{{ loginError }}</p>
        <button v-if="authMethods.local_enabled" class="primary wide" :disabled="loggingIn"><LoaderCircle v-if="loggingIn" class="spin" :size="18" /><DoorOpen v-else :size="18" />进入控制台</button>
        <div v-if="authMethods.local_enabled && authMethods.oidc_enabled" class="auth-divider"><span>或</span></div>
        <button v-if="authMethods.oidc_enabled" type="button" class="secondary wide" :disabled="loggingIn" @click="startOidcLogin"><LoaderCircle v-if="loggingIn" class="spin" :size="18" /><ShieldCheck v-else :size="18" />{{ authMethods.oidc_provider_label || '统一身份认证' }}</button>
        <div class="secure-note"><ShieldCheck :size="16" />访问行为将写入安全审计日志</div>
      </form>
    </section>
  </main>

  <div v-else class="app-shell">
    <aside :class="['sidebar', { open: sidebarOpen }]">
      <div class="sidebar-brand"><div class="brand-mark"><HardHat :size="22" /></div><div><strong>MineGuard</strong><span>AI CONTROL</span></div></div>
      <nav>
        <button v-for="item in navItems" :key="item.id" :class="{ active: activeView === item.id }" @click="selectView(item.id)">
          <component :is="item.icon" :size="19" /><span>{{ item.label }}</span><ChevronRight v-if="activeView === item.id" class="nav-arrow" :size="15" />
        </button>
      </nav>
      <div class="sidebar-health"><span :class="['pulse', { warning: connectionState !== 'online' }]" /><div><strong>{{ connectionState === 'online' ? '系统运行正常' : connectionState === 'reconnecting' ? '正在恢复连接' : '网络连接中断' }}</strong><small>{{ connectionState === 'online' ? '全部服务已连接' : '恢复后将自动重连' }}</small></div></div>
      <button class="user-box" @click="logout"><CircleUserRound :size="28" /><div><strong>{{ user.full_name }}</strong><span>{{ roleLabels[user.role] || user.role }}</span></div><LogOut :size="17" /></button>
    </aside>
    <div v-if="sidebarOpen" class="scrim" @click="sidebarOpen = false" />

    <section class="workspace">
      <header class="topbar">
        <button class="icon-button mobile-menu" title="打开导航" @click="sidebarOpen = true"><Menu :size="21" /></button>
        <div><h1>{{ titles[activeView][0] }}</h1><p>{{ titles[activeView][1] }}</p></div>
        <div class="top-actions">
          <span :class="['connection-badge', connectionState]">
            <Wifi v-if="connectionState === 'online'" :size="15" />
            <LoaderCircle v-else-if="connectionState === 'reconnecting'" class="spin" :size="15" />
            <WifiOff v-else :size="15" />
            {{ connectionState === 'online' ? '连接正常' : connectionState === 'reconnecting' ? `重连中 · 第 ${reconnectAttempt} 次` : '网络离线' }}
          </span>
          <span class="shift"><Clock3 :size="15" />{{ new Date().toLocaleDateString('zh-CN') }} 白班</span>
          <button class="icon-button" title="刷新数据" :disabled="loading" @click="loadAll"><RefreshCw :class="{ spin: loading }" :size="19" /></button>
          <button class="icon-button alert-button" title="告警通知" @click="selectView('events')"><Bell :size="19" /><b v-if="summary?.critical_events">{{ summary.critical_events }}</b></button>
        </div>
      </header>

      <div v-if="globalError" class="error-banner"><AlertTriangle :size="18" /><span>{{ globalError }}</span><button title="关闭" @click="globalError = ''"><X :size="17" /></button></div>
      <div v-if="loading && !summary" class="loading-state"><LoaderCircle class="spin" :size="30" /><span>正在连接生产数据</span></div>

      <div v-else class="content">
        <template v-if="activeView === 'dashboard' && summary">
          <section class="metric-grid">
            <article class="metric"><div class="metric-icon green"><Video :size="21" /></div><div><span>在线监控</span><strong>{{ summary.cameras_online }}<small>/ {{ summary.cameras_total }}</small></strong><em>可用率 {{ summary.system_health.camera_availability }}%</em></div></article>
            <article class="metric"><div class="metric-icon red"><Siren :size="21" /></div><div><span>待处置事件</span><strong>{{ summary.open_events }}</strong><em>{{ summary.critical_events }} 项严重告警</em></div></article>
            <article class="metric"><div class="metric-icon blue"><UsersRound :size="21" /></div><div><span>授权人员</span><strong>{{ summary.persons_total }}</strong><em>已纳入身份管理</em></div></article>
            <article class="metric"><div class="metric-icon amber"><Activity :size="21" /></div><div><span>今日识别事件</span><strong>{{ summary.today_events }}</strong><em>推理队列畅通</em></div></article>
            <article class="metric"><div class="metric-icon blue"><UsersRound :size="21" /></div><div><span>当前区域人数</span><strong>{{ summary.current_person_count }}</strong><em>{{ Object.keys(summary.area_occupancy).length }} 个区域已上报</em></div></article>
          </section>

          <section class="dashboard-grid">
            <div class="panel camera-panel">
              <div class="panel-head"><div><h2>重点区域监控</h2><span>实时点位状态</span></div><button class="text-button" @click="selectView('cameras')">全部点位<ChevronRight :size="16" /></button></div>
              <div class="monitor-grid">
                <article v-for="camera in overviewCameras" :key="camera.id" class="monitor-feed">
                  <CameraFeed class="feed-visual" :url="camera.playback_path" :status="camera.status" :code="camera.code" />
                  <footer><div><strong>{{ camera.name }}</strong><span>{{ camera.area }}</span></div><em>{{ camera.fps ? camera.fps + ' FPS' : '--' }}</em></footer>
                </article>
              </div>
            </div>
            <div class="panel event-panel">
              <div class="panel-head"><div><h2>实时告警</h2><span>按风险等级排序</span></div><button class="text-button" @click="selectView('events')">事件中心<ChevronRight :size="16" /></button></div>
              <div class="alert-list">
                <article v-for="event in summary.recent_events.slice(0, 5)" :key="event.id" class="alert-row">
                  <div :class="['severity-marker', event.severity]"><AlertTriangle v-if="event.severity === 'critical' || event.severity === 'high'" :size="17" /><Activity v-else :size="17" /></div>
                  <div><strong>{{ event.title }}</strong><span>{{ event.camera.name }} · {{ formatTime(event.occurred_at) }}</span></div>
                  <b :class="['tag', event.severity]">{{ severityLabels[event.severity] }}</b>
                </article>
                <div v-if="!summary.recent_events.length" class="empty-state"><Check :size="24" />暂无告警事件</div>
              </div>
            </div>
          </section>

          <section class="chart-grid">
            <div class="panel"><div class="panel-head"><div><h2>事件趋势</h2><span>最近 12 小时</span></div><Activity :size="19" /></div><div id="trend-chart" class="chart" /></div>
            <div class="panel"><div class="panel-head"><div><h2>风险等级分布</h2><span>全部事件</span></div><Gauge :size="19" /></div><div id="severity-chart" class="chart" /></div>
          </section>
        </template>

        <template v-else-if="activeView === 'cameras'">
          <section class="toolbar"><div class="search-box"><Search :size="17" /><input v-model="search" maxlength="100" placeholder="搜索名称、编号或区域" /></div><div class="toolbar-end"><span class="count-label">共 {{ cameraTotal }} 个点位</span><button v-if="user.role !== 'auditor'" class="primary" @click="openCameraCreation"><Plus :size="17" />新增点位</button></div></section>
          <section class="camera-list">
            <article v-for="camera in cameras.filter(c => `${c.name}${c.code}${c.area}`.toLowerCase().includes(search.toLowerCase()))" :key="camera.id" class="camera-card">
              <CameraFeed class="camera-preview" :url="camera.playback_path" :status="camera.status" :code="camera.code" />
              <div class="camera-info"><div class="camera-heading"><div><small>{{ camera.code }}</small><h3>{{ camera.name }}</h3><p>{{ camera.area }}</p></div><button v-if="user.role !== 'auditor'" class="icon-button compact" title="编辑监控点位" @click="openCameraEdit(camera)"><Pencil :size="15" /></button></div><dl><div><dt>帧率</dt><dd>{{ camera.fps || '--' }} FPS</dd></div><div><dt>延迟</dt><dd>{{ camera.latency_ms || '--' }} ms</dd></div></dl><div class="chips"><span v-for="item in camera.enabled_algorithms" :key="item">{{ item }}</span><span v-if="!camera.enabled_algorithms.length">未启用算法</span></div></div>
            </article>
          </section>
          <nav v-if="cameraTotal > pageSize" class="pager" aria-label="监控点位分页"><button title="上一页" :disabled="cameraPage <= 1" @click="changePage('cameras', cameraPage - 1)"><ChevronLeft :size="16" /></button><span>第 {{ cameraPage }} / {{ totalPages(cameraTotal) }} 页</span><button title="下一页" :disabled="cameraPage >= totalPages(cameraTotal)" @click="changePage('cameras', cameraPage + 1)"><ChevronRight :size="16" /></button></nav>
        </template>

        <template v-else-if="activeView === 'events'">
          <section class="toolbar"><div class="search-box"><Search :size="17" /><input v-model="search" maxlength="100" placeholder="搜索事件或监控点" /></div><div class="segmented"><button :class="{ active: eventStatusFilter === '' }" @click="eventStatusFilter = ''">全部</button><button :class="{ active: eventStatusFilter === 'open' }" @click="eventStatusFilter = 'open'">待处置</button><button :class="{ active: eventStatusFilter === 'acknowledged' }" @click="eventStatusFilter = 'acknowledged'">处理中</button><button :class="{ active: eventStatusFilter === 'resolved' }" @click="eventStatusFilter = 'resolved'">已闭环</button></div></section>
          <section class="table-panel">
            <table><thead><tr><th>风险</th><th>事件</th><th>监控点</th><th>置信度</th><th>发生时间</th><th>状态</th><th>操作</th></tr></thead>
              <tbody><tr v-for="event in filteredEvents" :key="event.id"><td><span :class="['severity-dot', event.severity]" />{{ severityLabels[event.severity] }}</td><td><strong>{{ event.title }}</strong><small>{{ typeLabels[event.event_type] || event.event_type }}{{ event.legal_hold ? ' · 法律保留' : '' }}</small></td><td>{{ event.camera.name }}<small>{{ event.camera.area }}</small></td><td>{{ (event.confidence * 100).toFixed(1) }}%</td><td>{{ formatTime(event.occurred_at) }}</td><td><span :class="['status-pill', event.status]">{{ statusLabels[event.status] }}</span></td><td><div class="row-actions"><button v-if="event.snapshot_url" title="查看事件快照" @click="openEventSnapshot(event)"><Eye :size="16" /></button><button v-if="event.status === 'open'" title="确认事件" @click="updateEvent(event, 'acknowledged')"><Check :size="16" /></button><button v-if="event.status === 'open' || event.status === 'acknowledged'" title="闭环事件" @click="updateEvent(event, 'resolved')"><ShieldCheck :size="16" /></button><button v-if="event.status === 'open'" title="标记误报" @click="updateEvent(event, 'false_positive')"><X :size="16" /></button><button v-if="user.role === 'admin'" :title="event.legal_hold ? '解除法律保留' : '设置法律保留'" @click="openEventLegalHold(event)"><Unlock v-if="event.legal_hold" :size="16" /><Lock v-else :size="16" /></button></div></td></tr></tbody>
            </table><div v-if="!filteredEvents.length" class="empty-state">没有符合条件的事件</div><nav v-if="eventTotal > pageSize" class="pager" aria-label="事件分页"><button title="上一页" :disabled="eventPage <= 1" @click="changePage('events', eventPage - 1)"><ChevronLeft :size="16" /></button><span>第 {{ eventPage }} / {{ totalPages(eventTotal) }} 页 · 共 {{ eventTotal }} 条</span><button title="下一页" :disabled="eventPage >= totalPages(eventTotal)" @click="changePage('events', eventPage + 1)"><ChevronRight :size="16" /></button></nav>
          </section>
        </template>

        <template v-else-if="activeView === 'persons'">
          <section class="toolbar"><div class="search-box"><Search :size="17" /><input v-model="search" maxlength="100" placeholder="搜索姓名、工号或部门" /></div><button v-if="user.role !== 'auditor'" class="primary" @click="openPersonCreation"><Plus :size="17" />登记人员</button></section>
          <section class="table-panel"><table><thead><tr><th>人员</th><th>工号</th><th>部门</th><th>身份类型</th><th>人脸信息</th><th>授权区域</th><th>状态</th><th>操作</th></tr></thead>
            <tbody><tr v-for="person in filteredPersons" :key="person.id"><td><div class="person-cell"><div class="avatar">{{ person.name.slice(-1) }}</div><strong>{{ person.name }}</strong></div></td><td>{{ person.employee_no }}</td><td>{{ person.department }}</td><td>{{ person.person_type === 'employee' ? '员工' : person.person_type }}</td><td><span :class="['status-pill', person.face_enrolled ? 'resolved' : 'offline']">{{ person.face_enrolled ? '已录入' : '未录入' }}</span></td><td><div class="chips"><span v-for="area in person.authorized_areas" :key="area">{{ area }}</span><span v-if="!person.authorized_areas.length">未授权</span></div></td><td><span :class="['status-pill', person.active ? 'online' : 'offline']">{{ person.active ? '在用' : '停用' }}</span></td><td><div v-if="user.role !== 'auditor'" class="row-actions"><button v-if="person.active" title="登记人脸" @click="openFaceEnrollment(person)"><ScanFace :size="16" /></button><button title="编辑人员" @click="openPersonEdit(person)"><Pencil :size="16" /></button><button :title="person.active ? '停用人员' : '启用人员'" @click="openPersonStatus(person)"><Power :size="16" /></button></div></td></tr></tbody>
          </table><div v-if="!filteredPersons.length" class="empty-state">暂无人员数据</div><nav v-if="personTotal > pageSize" class="pager" aria-label="人员分页"><button title="上一页" :disabled="personPage <= 1" @click="changePage('persons', personPage - 1)"><ChevronLeft :size="16" /></button><span>第 {{ personPage }} / {{ totalPages(personTotal) }} 页 · 共 {{ personTotal }} 人</span><button title="下一页" :disabled="personPage >= totalPages(personTotal)" @click="changePage('persons', personPage + 1)"><ChevronRight :size="16" /></button></nav></section>
          <section v-if="user.role === 'admin' || user.role === 'auditor'" class="table-panel face-template-table"><div class="panel-head"><div><h2>人脸模板治理</h2><span>登记依据、模型与密钥版本、吊销和法律保留</span></div><span class="count-label">{{ faceTemplateTotal }} 个模板</span></div><table><thead><tr><th>人员</th><th>模板</th><th>模型 / Provider</th><th>密钥版本</th><th>质量 / 活体</th><th>授权记录</th><th>登记时间</th><th>状态</th><th>操作</th></tr></thead>
            <tbody><tr v-for="template in faceTemplates" :key="template.id"><td><strong>{{ template.person?.name || `人员 #${template.person_id}` }}</strong><small>{{ template.person?.employee_no || '--' }}</small></td><td>#{{ template.id }}</td><td><strong>{{ template.model_version }}</strong><small>{{ template.provider }}</small><code v-if="template.model_sha256" class="hash-cell" :title="template.model_sha256">{{ template.model_sha256.slice(0, 12) }}...</code><small v-else>旧模板未绑定制品</small></td><td><code>{{ template.key_version }}</code></td><td>{{ (template.quality * 100).toFixed(1) }}% / {{ (template.liveness * 100).toFixed(1) }}%</td><td><small class="consent-reference" :title="template.consent_reference">{{ template.consent_reference }}</small></td><td>{{ formatTime(template.created_at) }}</td><td><span :class="['status-pill', template.active ? 'online' : 'offline']">{{ template.active ? '活动' : '已吊销' }}</span><small v-if="template.legal_hold">法律保留</small></td><td><div v-if="user.role === 'admin'" class="row-actions"><button v-if="template.active" title="吊销模板" @click="revokeFaceTemplate(template)"><X :size="16" /></button><button :title="template.legal_hold ? '解除法律保留' : '设置法律保留'" @click="openFaceTemplateLegalHold(template)"><Unlock v-if="template.legal_hold" :size="16" /><Lock v-else :size="16" /></button></div><span v-else>--</span></td></tr></tbody>
          </table><div v-if="!faceTemplates.length" class="empty-state">尚无人脸模板记录</div><nav v-if="faceTemplateTotal > pageSize" class="pager" aria-label="人脸模板分页"><button title="上一页" :disabled="faceTemplatePage <= 1" @click="changePage('face-templates', faceTemplatePage - 1)"><ChevronLeft :size="16" /></button><span>第 {{ faceTemplatePage }} / {{ totalPages(faceTemplateTotal) }} 页 · 共 {{ faceTemplateTotal }} 个</span><button title="下一页" :disabled="faceTemplatePage >= totalPages(faceTemplateTotal)" @click="changePage('face-templates', faceTemplatePage + 1)"><ChevronRight :size="16" /></button></nav></section>
        </template>

        <template v-else-if="activeView === 'algorithms'">
          <section class="algorithm-intro"><div><BrainCircuit :size="25" /><div><h2>边缘智能算法编排</h2><p>配置修改写入审计日志，生产模型切换需通过离线评估和影子运行。</p></div></div><span><ShieldCheck :size="16" />安全约束已启用</span></section>
          <section class="algorithm-list">
            <article v-for="algorithm in algorithms" :key="algorithm.id" class="algorithm-row">
              <div class="algo-icon"><Cpu v-if="algorithm.algorithm_type !== 'face_recognition'" :size="22" /><CircleUserRound v-else :size="22" /></div>
              <div class="algo-main"><div><h3>{{ algorithm.name }}</h3><span :class="['status-pill', algorithm.deployment_status]">{{ statusLabels[algorithm.deployment_status] || algorithm.deployment_status }}</span></div><p>{{ algorithm.algorithm_type }} · {{ algorithm.model_version }}</p><div class="algo-meta"><label class="algo-threshold">判定阈值 <input type="range" min="0" max="1" step="0.01" :value="algorithm.threshold" :disabled="user.role !== 'admin'" @change="updateAlgorithmThreshold(algorithm, $event)" /><strong>{{ algorithm.threshold.toFixed(2) }}</strong></label><span>更新于 {{ formatTime(algorithm.updated_at) }}</span></div></div>
              <button class="icon-button compact" title="查看算法过程与接入诊断" @click="selectedAlgorithmId = algorithm.id"><GitBranch :size="16" /></button><label v-if="user.role === 'admin'" class="switch" :title="algorithm.enabled ? '停用算法' : '启用算法'"><input type="checkbox" :checked="algorithm.enabled" @change="toggleAlgorithm(algorithm)" /><span /></label>
              <span v-else :class="['status-pill', algorithm.enabled ? 'online' : 'offline']">{{ algorithm.enabled ? '已启用' : '已停用' }}</span>
            </article>
          </section>
          <section v-if="selectedAlgorithm && algorithmGuide" class="algorithm-debug-panel">
            <header><div><small>算法过程与接入诊断</small><h2>{{ selectedAlgorithm.name }}</h2><p>{{ algorithmGuide.summary }}</p></div><span :class="['status-pill', selectedAlgorithm.deployment_status]">{{ statusLabels[selectedAlgorithm.deployment_status] || selectedAlgorithm.deployment_status }}</span></header>
            <div class="debug-io"><div><span>输入</span><strong>{{ algorithmGuide.input }}</strong></div><div><span>输出</span><strong>{{ algorithmGuide.output }}</strong></div><div><span>当前阈值</span><strong>{{ selectedAlgorithm.threshold.toFixed(2) }}</strong></div><div><span>模型版本</span><strong>{{ selectedAlgorithm.model_version }}</strong></div></div>
            <div class="debug-flow"><div v-for="(stage, index) in algorithmGuide.stages" :key="stage"><b>{{ index + 1 }}</b><span>{{ stage }}</span></div></div>
            <div class="debug-columns"><div><h3>当前生效配置</h3><pre>{{ JSON.stringify(selectedAlgorithm.config, null, 2) }}</pre></div><div><h3>模型制品与接入状态</h3><ul><li v-for="artifact in modelArtifacts.filter(item => item.algorithm_type === selectedAlgorithm.algorithm_type)" :key="artifact.id"><strong>{{ artifact.name }} · {{ artifact.model_version }}</strong><span>{{ artifact.approved ? '已准入' : '未准入' }} · {{ artifact.runtime }} · {{ artifact.sha256.slice(0, 12) }}</span></li><li v-if="!modelArtifacts.some(item => item.algorithm_type === selectedAlgorithm.algorithm_type)">尚未登记对应模型制品</li></ul><ul><li v-for="node in edgeNodes" :key="node.id"><strong>{{ node.name }}</strong><span>{{ node.status }} · 上报模型 {{ (node.telemetry.models || []).filter(item => item.algorithm_type === selectedAlgorithm.algorithm_type).length }} 个</span></li><li v-if="!edgeNodes.length">尚未有边缘节点上报运行状态</li></ul></div></div>
            <div class="debug-notes"><strong>功能边界</strong><span v-for="note in algorithmGuide.notes" :key="note">{{ note }}</span></div>
          </section>
          <section class="table-panel artifact-registry">
            <div class="panel-head"><div><h2>生产模型制品库</h2><span>只有摘要一致且审批通过的制品可由边缘节点加载</span></div><div class="artifact-head-actions"><span class="count-label">本页 {{ modelArtifacts.filter(item => item.approved).length }} 个已准入 · 共 {{ modelArtifactTotal }} 个</span><button v-if="user.role === 'admin'" class="primary" @click="openArtifactCreation"><Plus :size="16" />登记制品</button></div></div>
            <table class="artifact-table"><thead><tr><th>制品</th><th>运行时 / 许可证</th><th>来源</th><th>SHA-256</th><th>评估指标</th><th>审批状态</th><th>操作</th></tr></thead>
              <tbody><tr v-for="artifact in modelArtifacts" :key="artifact.id"><td><strong>{{ artifact.name }}</strong><small>{{ artifact.algorithm_type }} · {{ artifact.model_version }}</small></td><td><strong>{{ artifact.runtime }}</strong><small>{{ artifact.license_id }}</small></td><td><strong class="repository-cell">{{ artifact.source_repository }}</strong><small>commit {{ artifact.source_commit.slice(0, 12) }}</small></td><td><code class="hash-cell" :title="artifact.sha256">{{ artifact.sha256.slice(0, 12) }}…</code></td><td><small class="metrics-cell">{{ Object.keys(artifact.metrics).length ? Object.entries(artifact.metrics).map(([key, value]) => `${key}=${value}`).join(' · ') : '未填报' }}</small></td><td><span :class="['status-pill', artifact.approved ? 'approved' : 'pending']">{{ artifact.approved ? '已准入' : '待审批' }}</span><small v-if="artifact.approved_at">{{ formatTime(artifact.approved_at) }}</small></td><td><div v-if="user.role === 'admin'" class="row-actions"><button v-if="!artifact.approved" title="审批准入" @click="openArtifactApproval(artifact, true)"><PackageCheck :size="16" /></button><button v-else title="撤销准入" @click="openArtifactApproval(artifact, false)"><X :size="16" /></button></div><span v-else>--</span></td></tr></tbody>
            </table><div v-if="!modelArtifacts.length" class="empty-state">尚未登记模型制品</div><nav v-if="modelArtifactTotal > pageSize" class="pager" aria-label="模型制品分页"><button title="上一页" :disabled="modelArtifactPage <= 1" @click="changePage('model-artifacts', modelArtifactPage - 1)"><ChevronLeft :size="16" /></button><span>第 {{ modelArtifactPage }} / {{ totalPages(modelArtifactTotal) }} 页 · 共 {{ modelArtifactTotal }} 个</span><button title="下一页" :disabled="modelArtifactPage >= totalPages(modelArtifactTotal)" @click="changePage('model-artifacts', modelArtifactPage + 1)"><ChevronRight :size="16" /></button></nav>
          </section>
        </template>

        <template v-else-if="activeView === 'video-cases'">
          <section class="case-notice"><BookOpen :size="20" /><div><strong>{{ videoCaseManifest?.title || '离线真实视频案例基准' }}</strong><p>{{ videoCaseManifest?.limitations }}</p></div></section>
          <section class="case-grid">
            <article v-for="item in videoCaseManifest?.cases || []" :key="item.id" class="case-card">
              <video controls preload="metadata" :src="item.video_path" :aria-label="item.title" />
              <div class="case-card-body">
                <header><div><small>{{ item.scenario }}</small><h2>{{ item.title }}</h2></div><span class="status-pill approved">已基准</span></header>
                <div class="case-metrics"><div><span>分析帧</span><strong>{{ item.metrics.analyzed_frames }}</strong><small>/ {{ item.metrics.decoded_frames }}</small></div><div><span>检出覆盖</span><strong>{{ (item.metrics.detection_coverage * 100).toFixed(1) }}%</strong><small>{{ item.metrics.frames_with_people }} 帧</small></div><div><span>P50 / P95</span><strong>{{ item.metrics.latency_ms_p50 }} / {{ item.metrics.latency_ms_p95 }} ms</strong><small>均值 {{ item.metrics.latency_ms_mean }} ms</small></div><div><span>分析吞吐</span><strong>{{ item.metrics.effective_analysis_fps }} FPS</strong><small>每 {{ item.metrics.frame_sampling_interval }} 帧取样</small></div></div>
                <div class="case-events"><span>规则命中</span><b v-for="(count, name) in item.metrics.rule_events" :key="name">{{ typeLabels[name] || name }} {{ count }}</b><em v-if="!Object.keys(item.metrics.rule_events).length">未观察到规则命中</em></div>
                <footer><a :href="item.source_url" target="_blank" rel="noreferrer">Wikimedia Commons 来源</a><span>{{ item.license }} · {{ item.source_attribution }}</span></footer>
              </div>
            </article>
          </section>
          <section class="case-method"><strong>执行方法</strong><span>{{ videoCaseManifest?.method }}</span><small>生成时间：{{ videoCaseManifest ? formatTime(videoCaseManifest.generated_at) : '--' }}</small></section>
        </template>

        <template v-else-if="activeView === 'rules'">
          <section class="toolbar"><div class="section-note"><ShieldCheck :size="18" /><span>规则命中后按风险等级、区域和冷却窗口合并通知</span></div><button v-if="user.role === 'admin'" class="primary" @click="openRuleCreation"><Plus :size="17" />新增规则</button></section>
          <section class="rule-list">
            <article v-for="rule in alertRules" :key="rule.id" class="rule-row">
              <div :class="['rule-indicator', rule.enabled ? 'enabled' : 'disabled']"><Siren :size="21" /></div>
              <div class="rule-main"><div><h3>{{ rule.name }}</h3><span :class="['status-pill', rule.enabled ? 'online' : 'offline']">{{ rule.enabled ? '已启用' : '已停用' }}</span></div><p>{{ rule.event_types.map(x => typeLabels[x] || x).join('、') }}</p><div class="rule-meta"><span>最低风险 <strong>{{ severityLabels[rule.minimum_severity] }}</strong></span><span>区域 <strong>{{ rule.areas.length ? rule.areas.join('、') : '全部' }}</strong></span><span>通道 <strong>{{ rule.channels.join(' / ') }}</strong></span><span>抑制 <strong>{{ rule.cooldown_seconds }} 秒</strong></span></div></div>
              <div v-if="user.role === 'admin'" class="rule-actions"><button class="icon-button compact" title="编辑规则" @click="openRuleEdit(rule)"><Pencil :size="15" /></button><label class="switch" :title="rule.enabled ? '停用规则' : '启用规则'"><input type="checkbox" :checked="rule.enabled" @change="toggleRule(rule)" /><span /></label></div>
            </article>
            <div v-if="!alertRules.length" class="empty-state">暂无告警规则</div><nav v-if="alertRuleTotal > pageSize" class="pager" aria-label="告警规则分页"><button title="上一页" :disabled="alertRulePage <= 1" @click="changePage('alert-rules', alertRulePage - 1)"><ChevronLeft :size="16" /></button><span>第 {{ alertRulePage }} / {{ totalPages(alertRuleTotal) }} 页 · 共 {{ alertRuleTotal }} 条</span><button title="下一页" :disabled="alertRulePage >= totalPages(alertRuleTotal)" @click="changePage('alert-rules', alertRulePage + 1)"><ChevronRight :size="16" /></button></nav>
          </section>
          <section class="table-panel delivery-table"><div class="panel-head"><div><h2>通知投递</h2><span>规则命中、重试与送达记录</span></div><span class="count-label">{{ deliveryTotal }} 条</span></div><table><thead><tr><th>创建时间</th><th>事件 ID</th><th>通道</th><th>目标</th><th>状态</th><th>尝试</th><th>错误</th><th>操作</th></tr></thead>
            <tbody><tr v-for="delivery in deliveries" :key="delivery.id"><td>{{ formatTime(delivery.created_at) }}</td><td>#{{ delivery.event_id }}</td><td>{{ delivery.channel }}</td><td>{{ delivery.target || '默认目标' }}</td><td><span :class="['status-pill', delivery.status]">{{ statusLabels[delivery.status] || delivery.status }}</span></td><td>{{ delivery.attempts }}</td><td><small class="delivery-error">{{ delivery.last_error || '--' }}</small></td><td><button v-if="user.role === 'admin' && delivery.status === 'failed'" class="icon-button compact" title="重新投递" @click="retryDelivery(delivery)"><RefreshCw :size="15" /></button></td></tr></tbody>
          </table><div v-if="!deliveries.length" class="empty-state">暂无通知投递记录</div><nav v-if="deliveryTotal > pageSize" class="pager" aria-label="通知投递分页"><button title="上一页" :disabled="deliveryPage <= 1" @click="changePage('deliveries', deliveryPage - 1)"><ChevronLeft :size="16" /></button><span>第 {{ deliveryPage }} / {{ totalPages(deliveryTotal) }} 页 · 共 {{ deliveryTotal }} 条</span><button title="下一页" :disabled="deliveryPage >= totalPages(deliveryTotal)" @click="changePage('deliveries', deliveryPage + 1)"><ChevronRight :size="16" /></button></nav></section>
        </template>

        <template v-else-if="activeView === 'administration'">
          <section v-if="user.role === 'admin'" class="admin-users">
            <div class="panel-head"><div><h2>平台账号</h2><span>角色、区域与启停状态</span></div><div class="toolbar-end"><span class="count-label">共 {{ userTotal }} 个</span><button class="primary" @click="openUserCreation"><Plus :size="17" />新增账号</button></div></div>
            <div class="user-grid"><article v-for="account in users" :key="account.id"><div class="avatar"><UserCog :size="18" /></div><div class="account-identity"><strong>{{ account.full_name }}</strong><span>@{{ account.username }} · {{ account.identity_provider === 'local' ? '本地账号' : '统一身份' }}</span><small>{{ accountScopeLabel(account) }}</small></div><select :value="account.role" :disabled="account.identity_provider !== 'local'" :title="account.identity_provider === 'local' ? '账号角色' : '角色由身份提供方组映射管理'" @change="updateAccountRole(account, $event)"><option value="operator">值班员</option><option value="auditor">审计员</option><option value="admin">管理员</option></select><div class="account-actions"><button v-if="account.identity_provider === 'local'" class="icon-button compact" title="修改角色与区域" @click="openAccountAccess(account)"><ShieldCheck :size="15" /></button><button v-if="account.identity_provider === 'local'" class="icon-button compact" title="重置密码" @click="openPasswordReset(account)"><KeyRound :size="15" /></button><button class="icon-button compact" :title="account.active ? '停用账号' : '启用账号'" @click="toggleAccount(account)"><Power :size="15" /></button></div></article></div>
            <nav v-if="userTotal > pageSize" class="pager" aria-label="平台账号分页"><button title="上一页" :disabled="userPage <= 1" @click="changePage('users', userPage - 1)"><ChevronLeft :size="16" /></button><span>第 {{ userPage }} / {{ totalPages(userTotal) }} 页 · 共 {{ userTotal }} 个</span><button title="下一页" :disabled="userPage >= totalPages(userTotal)" @click="changePage('users', userPage + 1)"><ChevronRight :size="16" /></button></nav>
          </section>
          <section v-if="user.role === 'admin'" class="admin-role-grid">
            <article v-for="role in roleDefinitions" :key="role.id"><div class="system-icon blue"><ShieldCheck :size="19" /></div><h3>{{ role.name }}</h3><p>{{ role.description }}</p><div class="chips"><span v-for="permission in role.permissions" :key="permission">{{ permission }}</span></div></article>
          </section>
          <section v-if="user.role === 'admin' && llmConfiguration" class="llm-config-panel">
            <div class="panel-head"><div><h2>大模型配置</h2><span>仅保存密钥环境变量引用；实际密钥不写入数据库、不返回浏览器</span></div><span :class="['status-pill', llmConfiguration.enabled ? 'online' : 'offline']">{{ llmConfiguration.enabled ? '已启用' : '未启用' }}</span></div>
            <div class="form-grid"><label class="switch-field">启用模型服务<label class="switch"><input v-model="llmConfiguration.enabled" type="checkbox" /><span /></label></label><label>提供方<select v-model="llmConfiguration.provider"><option value="openai_compatible">OpenAI 兼容接口</option><option value="ollama">Ollama</option></select></label><label>服务地址<input v-model="llmConfiguration.base_url" type="url" required /></label><label>模型名称<input v-model="llmConfiguration.model" required /></label><label>密钥环境变量<input v-model="llmConfiguration.api_key_env" pattern="MINEGUARD_[A-Z0-9_]+" required /><small>{{ llmConfiguration.api_key_configured ? '当前运行环境已检测到密钥' : '当前运行环境未检测到此密钥' }}</small></label><label>温度<input v-model.number="llmConfiguration.temperature" type="number" min="0" max="2" step="0.1" required /></label><label>最大输出 Token<input v-model.number="llmConfiguration.max_tokens" type="number" min="64" max="32768" step="64" required /></label></div>
            <label>系统提示词<textarea v-model="llmConfiguration.system_prompt" rows="3" maxlength="4000" /></label><div class="llm-config-footer"><small>最后更新：{{ formatTime(llmConfiguration.updated_at) }}</small><button class="primary" :disabled="savingLlmConfiguration" @click="saveLlmConfiguration"><Check :size="16" />{{ savingLlmConfiguration ? '保存中' : '保存配置' }}</button></div>
          </section>
          <section class="table-panel audit-table"><table><thead><tr><th>时间</th><th>操作者 ID</th><th>操作</th><th>资源</th><th>资源 ID</th><th>来源 IP</th><th>详情</th></tr></thead>
            <tbody><tr v-for="log in auditLogs" :key="log.id"><td>{{ formatTime(log.created_at) }}</td><td>{{ log.user_id || 'system' }}</td><td><strong>{{ log.action }}</strong><small v-if="log.legal_hold">法律保留</small></td><td>{{ log.resource_type }}</td><td>{{ log.resource_id || '--' }}</td><td>{{ log.ip_address || '--' }}</td><td><small class="audit-detail">{{ JSON.stringify(log.detail) }}</small></td></tr></tbody>
          </table><div v-if="!auditLogs.length" class="empty-state">暂无审计记录</div><nav v-if="auditTotal > pageSize" class="pager" aria-label="审计日志分页"><button title="上一页" :disabled="auditPage <= 1" @click="changePage('audit', auditPage - 1)"><ChevronLeft :size="16" /></button><span>第 {{ auditPage }} / {{ totalPages(auditTotal) }} 页 · 共 {{ auditTotal }} 条</span><button title="下一页" :disabled="auditPage >= totalPages(auditTotal)" @click="changePage('audit', auditPage + 1)"><ChevronRight :size="16" /></button></nav></section>
        </template>

        <template v-else-if="activeView === 'system'">
          <section v-if="summary?.operational_alerts.length" class="error-banner"><AlertTriangle :size="18" /><span>{{ summary.operational_alerts.map(alert => alert.message).join('；') }}</span></section>
          <section class="toolbar system-toolbar"><div class="section-note"><ShieldCheck :size="18" /><span>认证模式 {{ capabilities.authentication_mode || 'local-jwt-refresh' }} · Access {{ capabilities.access_token_minutes || 30 }} 分钟</span></div><div class="toolbar-end"><button v-if="user.role === 'admin'" class="secondary" @click="openEdgeRegistration"><Plus :size="17" />注册边缘节点</button><button v-if="user.identity_provider === 'local'" class="secondary" @click="modal = 'password'"><UserCog :size="17" />修改我的密码</button></div></section>
          <section class="system-grid">
            <article><div :class="['system-icon', summary?.system_health.worker_status === 'online' ? 'green' : 'amber']"><RefreshCw :size="21" /></div><h3>后台任务服务</h3><strong>{{ summary?.system_health.worker_status === 'online' ? '运行正常' : summary?.system_health.worker_status === 'degraded' ? '自动恢复中' : '心跳已中断' }}</strong><p>{{ Number(summary?.system_health.worker_instances_online || 0) }} 个实例在线 · 最后心跳 {{ Number(summary?.system_health.worker_last_seen_seconds ?? -1) < 0 ? '尚未收到' : `${summary?.system_health.worker_last_seen_seconds} 秒前` }}</p></article>
            <article><div class="system-icon green"><Activity :size="21" /></div><h3>API 服务</h3><strong>运行正常</strong><p>P95 {{ summary?.system_health.api_latency_ms || '--' }} ms · 当前实例</p></article>
            <article><div class="system-icon blue"><Database :size="21" /></div><h3>通知投递队列</h3><strong>{{ summary?.system_health.event_queue_depth || 0 }} 个待处理</strong><p>{{ Number(summary?.system_health.event_queue_depth || 0) > 0 ? '包含待发或失败重试' : '当前无积压' }}</p></article>
            <article><div :class="['system-icon', summary?.system_health.media_gateway_status === 'online' ? 'green' : 'amber']"><Wifi :size="21" /></div><h3>视频接入</h3><strong>{{ summary?.system_health.media_gateway_status === 'recovering' ? '媒体路径自动恢复中' : `${summary?.cameras_online || 0} / ${summary?.cameras_total || 0} 在线` }}</strong><p>网关 {{ summary?.system_health.media_gateway_status === 'online' ? '已对账' : summary?.system_health.media_gateway_status === 'recovering' ? '连接重试中' : '未配置' }} · 可用率 {{ summary?.system_health.camera_availability || 0 }}%</p></article>
            <article><div class="system-icon green"><ShieldCheck :size="21" /></div><h3>安全与区域权限</h3><strong>角色 + 生产区域</strong><p>媒体分片鉴权 · 登录与变更可追溯</p></article>
            <article><div :class="['system-icon', capabilities.face_recognition_enabled ? 'green' : 'amber']"><ScanFace :size="21" /></div><h3>人脸 Provider</h3><strong>{{ capabilities.face_recognition_enabled ? '已安全启用' : '等待部署配置' }}</strong><p>{{ capabilities.biometric_template_encryption || 'AES-256-GCM' }} 模板保护</p></article>
            <article><div :class="['system-icon', capabilities.notification_gateway_configured ? 'green' : 'amber']"><Bell :size="21" /></div><h3>通知网关</h3><strong>{{ capabilities.notification_gateway_configured ? '外部通道已连接' : '仅控制台通道' }}</strong><p>{{ capabilities.live_update_mode || 'resilient-polling-20s' }}</p></article>
            <article><div :class="['system-icon', capabilities.approved_model_enforcement ? 'green' : 'amber']"><Cpu :size="21" /></div><h3>模型供应链</h3><strong>{{ capabilities.approved_model_enforcement ? '制品准入已强制' : '开发模式' }}</strong><p>{{ capabilities.four_eyes_model_approval ? '四眼审批已启用' : '单管理员审批' }}</p></article>
            <article><div :class="['system-icon', Number(summary?.system_health.snapshot_legal_hold_pending || 0) > 0 ? 'amber' : capabilities.snapshot_storage_enabled ? 'green' : 'amber']"><Eye :size="21" /></div><h3>事件快照存储</h3><strong>{{ Number(summary?.system_health.snapshot_legal_hold_pending || 0) > 0 ? '法律保留自动对账中' : capabilities.snapshot_storage_enabled ? '对象存储已启用' : '当前未启用' }}</strong><p>{{ Number(summary?.system_health.snapshot_legal_hold_pending || 0) > 0 ? `${summary?.system_health.snapshot_legal_hold_pending} 个持久任务等待恢复` : '区域授权访问 · 短时签名 · 法律保留' }}</p></article>
          </section>
          <section class="panel runtime-panel"><div class="panel-head"><div><h2>运行组件</h2><span>部署拓扑状态</span></div><Gauge :size="19" /></div><div class="runtime-list"><div><span class="pulse" /><strong>FastAPI 控制服务</strong><em>healthy</em></div><div><span class="pulse" /><strong>PostgreSQL 数据库</strong><em>connected</em></div><div><span :class="['pulse', { warning: !edgeNodeTotal }]" /><strong>GPU 推理工作节点</strong><em>{{ edgeNodeTotal ? `${edgeNodeTotal} 个已注册` : '等待部署环境注册' }}</em></div><div><span :class="['pulse', { warning: Number(summary?.cameras_online || 0) === 0 }]" /><strong>RTSP / HLS 媒体链路</strong><em>{{ Number(summary?.cameras_online || 0) }} 路摄像头正在上报</em></div></div></section>
          <section class="edge-node-grid"><article v-for="node in edgeNodes" :key="node.id"><header><div><span :class="['pulse', { warning: node.status !== 'online' || Number(node.telemetry.dead_letter_depth || 0) > 0 || edgeOutboxUtilization(node) >= 0.8 }]" /><div><h3>{{ node.name }}</h3><small>{{ node.code }} · {{ node.software_version || '尚未上报版本' }}</small></div></div><div class="node-head-actions"><b :class="['status-pill', node.status]">{{ node.active ? (statusLabels[node.status] || node.status) : '已停用' }}</b><button v-if="user.role === 'admin'" class="icon-button compact" title="编辑节点绑定" @click="openEdgeEdit(node)"><Pencil :size="14" /></button><button v-if="user.role === 'admin'" class="icon-button compact" :title="node.active ? '停用节点' : '启用节点'" @click="setEdgeNodeActive(node)"><Power :size="14" /></button><button v-if="user.role === 'admin'" class="icon-button compact" title="轮换节点密钥" @click="rotateEdgeKey(node)"><RefreshCw :size="14" /></button></div></header><dl><div><dt>GPU</dt><dd>{{ node.telemetry.gpu_healthy === false ? '故障' : node.telemetry.gpu_utilization !== undefined ? (node.telemetry.gpu_utilization * 100).toFixed(0) + '%' : '--' }}</dd></div><div><dt>显存</dt><dd>{{ node.telemetry.gpu_healthy === false ? '故障' : node.telemetry.gpu_memory_utilization !== undefined ? (node.telemetry.gpu_memory_utilization * 100).toFixed(0) + '%' : '--' }}</dd></div><div><dt>队列</dt><dd :class="{ 'danger-text': edgeOutboxUtilization(node) >= 0.8 }">{{ Number(node.telemetry.queue_depth || 0) + Number(node.telemetry.dead_letter_depth || 0) }} / {{ node.telemetry.outbox_capacity || 100000 }}</dd></div><div><dt>隔离</dt><dd :class="{ 'danger-text': Number(node.telemetry.dead_letter_depth || 0) > 0 }">{{ node.telemetry.dead_letter_depth ?? 0 }}</dd></div><div><dt>摄像头</dt><dd>{{ node.camera_ids.length }}</dd></div></dl><div class="node-models"><div class="node-model-summary"><span>已报告模型 {{ node.telemetry.models?.length || 0 }}</span><b v-if="node.telemetry.unapproved_models?.length">{{ node.telemetry.unapproved_models.length }} 个未准入</b></div><div v-for="model in node.telemetry.models || []" :key="`${model.algorithm_type}:${model.sha256}`" :class="['node-model', { rejected: node.telemetry.unapproved_models?.some(item => item.sha256 === model.sha256) }]"><span>{{ model.algorithm_type }} · {{ model.model_version }}</span><code>{{ model.sha256.slice(0, 10) }}</code></div><div v-for="camera in (node.telemetry.cameras || []).filter(item => item.errors.length)" :key="`camera-error:${camera.camera_id}`" class="node-model rejected"><span>摄像头 #{{ camera.camera_id }}</span><code :title="camera.errors.join(', ')">{{ camera.errors.join(' · ') }}</code></div></div><p>最后心跳 {{ formatTime(node.last_seen_at) }}</p></article><div v-if="!edgeNodes.length" class="empty-state">尚未注册边缘推理节点</div></section><nav v-if="edgeNodeTotal > pageSize" class="pager" aria-label="边缘节点分页"><button title="上一页" :disabled="edgeNodePage <= 1" @click="changePage('edge-nodes', edgeNodePage - 1)"><ChevronLeft :size="16" /></button><span>第 {{ edgeNodePage }} / {{ totalPages(edgeNodeTotal) }} 页 · 共 {{ edgeNodeTotal }} 个</span><button title="下一页" :disabled="edgeNodePage >= totalPages(edgeNodeTotal)" @click="changePage('edge-nodes', edgeNodePage + 1)"><ChevronRight :size="16" /></button></nav>
        </template>
      </div>
    </section>

    <div v-if="modal" class="modal-backdrop" @click.self="closeModal">
      <form :class="['modal', { 'modal-wide': modal && ['artifact', 'rule', 'edge', 'event-snapshot'].includes(modal) }]" @submit.prevent="submitModal">
        <header><div><h2>{{ modalTitle }}</h2><p>{{ modalDescription }}</p></div><button type="button" class="icon-button" title="关闭" @click="closeModal"><X :size="19" /></button></header>
        <template v-if="modal === 'camera' || modal === 'camera-edit'"><label>设备编号<input v-model="cameraForm.code" :disabled="modal === 'camera-edit'" placeholder="CAM-005" required /></label><label>点位名称<input v-model="cameraForm.name" placeholder="例如：副井口西侧" required /></label><label>所属区域<input v-model="cameraForm.area" placeholder="例如：副井口" required /></label><label>RTSP / RTSPS 源地址<input v-model="cameraForm.stream_url" placeholder="编辑时留空保持现有地址" :required="modal === 'camera'" /></label><fieldset class="selection-group"><legend>启用算法</legend><div class="selection-grid"><label v-for="algorithmType in cameraAlgorithmOptions" :key="algorithmType" class="check-option"><input v-model="cameraForm.enabled_algorithms" type="checkbox" :value="algorithmType" /><span>{{ typeLabels[algorithmType] || algorithmType }}</span></label></div><p v-if="!cameraAlgorithmOptions.length" class="field-empty">尚无可配置算法</p></fieldset></template>
        <template v-else-if="modal === 'event-snapshot'"><div class="snapshot-viewer"><div v-if="snapshotLoading" class="snapshot-state"><LoaderCircle class="spin" :size="26" /><span>正在获取授权快照</span></div><img v-else-if="snapshotAccessUrl" :src="snapshotAccessUrl" :alt="selectedEvent?.title || '事件快照'" @error="handleSnapshotLoadError" /><div v-else class="snapshot-state error"><AlertTriangle :size="24" /><span>{{ snapshotError || '事件没有可用快照' }}</span></div></div></template>
        <template v-else-if="modal === 'person' || modal === 'person-edit'"><label>工号<input v-model="personForm.employee_no" :disabled="modal === 'person-edit'" placeholder="M20260019" required /></label><label>姓名<input v-model="personForm.name" required /></label><label>所属部门<input v-model="personForm.department" placeholder="例如：采掘二队" required /></label><label>身份类型<select v-model="personForm.person_type"><option value="employee">员工</option><option value="contractor">承包商</option><option value="visitor">访客</option></select></label><label>授权区域<input v-model="personAreasText" placeholder="主井口，运输巷道" /></label></template>
        <template v-else-if="modal === 'person-status'"><div :class="['approval-notice', { danger: !pendingPersonActive }]"><Power :size="18" /><p>{{ pendingPersonActive ? '启用后该人员可重新分配区域授权；此前吊销的人脸模板不会自动恢复。' : '停用将立即吊销该人员全部活动人脸模板并清除登记状态，重新启用后必须重新登记。' }}</p></div></template>
        <template v-else-if="modal === 'event-hold'"><label>变更依据<textarea v-model="legalHoldReason" rows="4" minlength="3" maxlength="500" placeholder="填写事故调查、监管冻结或解除保留的工单依据" required /></label><div :class="['approval-notice', { danger: selectedEvent?.legal_hold }]"><Lock v-if="!selectedEvent?.legal_hold" :size="18" /><Unlock v-else :size="18" /><p>{{ selectedEvent?.legal_hold ? '解除后，事件将在达到留存期限且没有待处理通知时进入自动清理范围。' : '设置后，事件、通知投递和关联审计将跳过自动清理，直至管理员记录依据并解除。' }}</p></div></template>
        <template v-else-if="modal === 'face-hold'"><label>变更依据<textarea v-model="legalHoldReason" rows="4" minlength="3" maxlength="500" placeholder="填写调查、监管冻结或解除保留的工单依据" required /></label><div :class="['approval-notice', { danger: selectedFaceTemplate?.legal_hold }]"><Lock v-if="!selectedFaceTemplate?.legal_hold" :size="18" /><Unlock v-else :size="18" /><p>{{ selectedFaceTemplate?.legal_hold ? '解除后，已吊销模板在达到留存期限时会进入自动销毁范围。' : '设置后，即使模板已吊销也不会被自动销毁，关联审计记录同样保留。' }}</p></div></template>
        <template v-else-if="modal === 'rule'">
          <div class="form-grid"><label>规则名称<input v-model="ruleForm.name" placeholder="例如：井口未授权进入" required /></label><label>最低风险<select v-model="ruleForm.minimum_severity"><option value="low">低</option><option value="medium">中</option><option value="high">高</option><option value="critical">严重</option></select></label><label>生产区域<input v-model="ruleAreasText" placeholder="留空表示全部区域；多个区域用逗号分隔" /></label><label>冷却时间（秒）<input v-model.number="ruleForm.cooldown_seconds" type="number" min="0" max="86400" required /></label></div>
          <fieldset class="selection-group"><legend>事件类型</legend><div class="selection-grid"><label v-for="option in ruleEventOptions" :key="option.value" class="check-option"><input v-model="ruleForm.event_types" type="checkbox" :value="option.value" /><span>{{ option.label }}</span></label></div></fieldset>
          <fieldset class="selection-group"><legend>通知通道</legend><div class="selection-grid"><label v-for="option in notificationChannelOptions" :key="option.value" class="check-option"><input v-model="ruleForm.channels" type="checkbox" :value="option.value" /><span>{{ option.label }}</span></label></div></fieldset>
          <div v-if="ruleForm.channels.some(channel => channel !== 'console')" class="form-grid target-grid"><label v-for="channel in ruleForm.channels.filter(item => item !== 'console')" :key="channel">{{ notificationChannelOptions.find(item => item.value === channel)?.label }}目标标识<input v-model="ruleForm.channel_targets[channel]" maxlength="100" placeholder="留空使用网关默认目标" pattern="[a-zA-Z0-9_.:-]+" /></label></div>
        </template>
        <template v-else-if="modal === 'user'"><label>用户名<input v-model="userForm.username" autocomplete="off" placeholder="operator02" required /></label><label>姓名<input v-model="userForm.full_name" required /></label><label>初始密码<input v-model="userForm.password" type="password" autocomplete="new-password" minlength="12" placeholder="至少 12 位，含大小写字母与数字" required /></label><label>角色<select v-model="userForm.role"><option value="operator">值班员</option><option value="auditor">审计员</option><option value="admin">管理员</option></select></label><label v-if="userForm.role !== 'admin'">生产区域<input v-model="userAreasText" placeholder="主井口，运输巷道" /></label><div v-if="userForm.role !== 'admin'" class="biometric-notice"><ShieldCheck :size="18" /><p>未填写区域时账号可以登录，但不能查看任何摄像头、事件、人员或生产汇总。</p></div></template>
        <template v-else-if="modal === 'user-access'"><label>角色<select v-model="selectedAccountRole"><option value="operator">值班员</option><option value="auditor">审计员</option><option value="admin">管理员</option></select></label><label v-if="selectedAccountRole !== 'admin'">生产区域<input v-model="userAreasText" placeholder="主井口，运输巷道" /></label><div class="biometric-notice"><ShieldCheck :size="18" /><p>{{ selectedAccountRole === 'admin' ? '管理员拥有全部生产区域权限。' : '保存后仅能访问列出的区域；空范围表示无生产数据权限。' }} 变更会立即撤销该账号全部现有会话。</p></div></template>
        <template v-else-if="modal === 'password'"><label>当前密码<input v-model="passwordForm.current_password" type="password" autocomplete="current-password" minlength="8" required /></label><label>新密码<input v-model="passwordForm.new_password" type="password" autocomplete="new-password" minlength="12" placeholder="至少 12 位，含大小写字母与数字" required /></label><div class="biometric-notice"><ShieldCheck :size="18" /><p>保存后当前 access token 和所有设备的 refresh 会话都会撤销，需要重新登录。</p></div></template>
        <template v-else-if="modal === 'reset-password'"><label>新密码<input v-model="resetPasswordValue" type="password" autocomplete="new-password" minlength="12" placeholder="至少 12 位，含大小写字母与数字" required /></label><div class="biometric-notice"><ShieldCheck :size="18" /><p>重置后该账号所有 access token 和 refresh 会话立即失效，用户需要使用新密码重新登录。</p></div></template>
        <template v-else-if="modal === 'edge'"><template v-if="!issuedEdgeKey"><div class="form-grid"><label>节点编号<input v-model="edgeForm.code" :disabled="Boolean(selectedEdgeNode)" placeholder="edge-shaft-01" pattern="[a-zA-Z0-9_.-]+" required /></label><label>节点名称<input v-model="edgeForm.name" placeholder="主井口 GPU 节点" required /></label></div><fieldset class="selection-group"><legend>允许处理的摄像头</legend><div class="selection-grid camera-selection"><label v-for="camera in edgeCameraOptions" :key="camera.id" class="check-option"><input v-model="edgeForm.camera_ids" type="checkbox" :value="camera.id" /><span>{{ camera.code }} · {{ camera.name }}</span></label></div><p v-if="!edgeCameraOptions.length" class="field-empty">尚无可绑定摄像头</p></fieldset></template><div v-else class="issued-secret"><KeyRound :size="21" /><div><strong>节点密钥已签发</strong><p>{{ issuedEdgeKey }}</p><small>关闭后无法再次查看。请立即写入节点密钥管理系统。</small></div></div></template>
        <template v-else-if="modal === 'artifact'"><div class="form-grid"><label>制品名称<input v-model="artifactForm.name" placeholder="helmet-detector" required /></label><label>算法类型<input v-model="artifactForm.algorithm_type" pattern="[a-z0-9_.-]+" placeholder="object_detection" required /></label><label>模型版本<input v-model="artifactForm.model_version" placeholder="1.4.0" required /></label><label>推理运行时<input v-model="artifactForm.runtime" placeholder="tensorrt-10" required /></label><label>许可证 SPDX 标识<input v-model="artifactForm.license_id" placeholder="Apache-2.0" required /></label><label>源码提交<input v-model="artifactForm.source_commit" pattern="[a-fA-F0-9]{7,64}" placeholder="40 位 Git commit" required /></label></div><label>模型文件 SHA-256<input v-model="artifactForm.sha256" pattern="[a-fA-F0-9]{64}" minlength="64" maxlength="64" placeholder="64 位十六进制摘要" required /></label><label>源码仓库<input v-model="artifactForm.source_repository" type="url" placeholder="https://github.com/organization/repository" required /></label><label>离线评估指标（JSON 对象）<textarea v-model="artifactMetricsJson" rows="3" placeholder='{"mAP50": 0.91, "recall": 0.94}' /></label><div class="biometric-notice"><ShieldCheck :size="18" /><p>登记不会直接部署模型。生产环境还需要另一名管理员审批，边缘节点会再次核对本地文件摘要与 Triton 报告。</p></div></template>
        <template v-else-if="modal === 'artifact-approval'"><label>审批结论<select v-model="artifactApproval.approved"><option :value="true">批准生产准入</option><option :value="false">撤销生产准入</option></select></label><label>审批原因<textarea v-model="artifactApproval.reason" rows="4" minlength="3" maxlength="500" placeholder="记录评估、许可证或撤销依据" required /></label><div :class="['approval-notice', { danger: !artifactApproval.approved }]"><PackageCheck :size="18" /><p>{{ artifactApproval.approved ? '批准后，摘要完全一致且自检就绪的边缘模型才能上报生产事件。' : '撤销后，仍报告该制品的边缘节点会在下一次心跳时降级并停止生产事件上报。' }}</p></div></template>
        <template v-else><label>授权/告知记录编号<input v-model="faceConsentReference" placeholder="CONSENT-2026-0001" minlength="3" required /></label><label class="file-field">登记图像<input type="file" accept="image/jpeg,image/png,image/webp" required @change="chooseFaceImage" /><span><Upload :size="17" />{{ faceImage?.name || '选择 JPEG、PNG 或 WebP 图像' }}</span></label><div class="biometric-notice"><ShieldCheck :size="18" /><p>图像仅发送至内网推理服务，不保存原图；模板使用 AES-256-GCM 加密。低质量、多张人脸或活体失败均会拒绝登记。</p></div></template>
        <footer v-if="modal === 'event-snapshot'"><button v-if="snapshotError" type="button" class="secondary" :disabled="snapshotLoading" @click="loadEventSnapshot"><RefreshCw :class="{ spin: snapshotLoading }" :size="16" />重新加载</button><button type="button" class="primary" @click="closeModal">关闭</button></footer>
        <footer v-else><button type="button" class="secondary" @click="closeModal">{{ modal === 'edge' && issuedEdgeKey ? '关闭' : '取消' }}</button><button v-if="modal !== 'edge' || !issuedEdgeKey" class="primary"><Check :size="17" />确认保存</button></footer>
      </form>
    </div>
  </div>
</template>
