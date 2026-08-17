<script setup>
import { computed, onMounted, ref } from 'vue'

const loading = ref(true)
const loggedIn = ref(false)
const error = ref('')
const username = ref('')
const password = ref('')
const logs = ref([])
const projects = ref([])
const selectedProject = ref('all')
const selectedEvent = ref('all')
const ipSearch = ref('')

const filteredLogs = computed(() => logs.value.filter(log => {
  if (selectedProject.value !== 'all' && log.project !== selectedProject.value) return false
  if (selectedEvent.value !== 'all' && log.event !== selectedEvent.value) return false
  if (ipSearch.value && !String(log.ip || '').includes(ipSearch.value.trim())) return false
  return true
}))

const eventTypes = computed(() => [...new Set(logs.value.map(x => x.event).filter(Boolean))].sort())

function formatDate(value) {
  return new Date(value).toLocaleString()
}

async function loadLogs() {
  loading.value = true
  error.value = ''
  try {
    const res = await fetch('/api/dashboard?limit=500', { credentials: 'include' })
    if (res.status === 401 || res.status === 403) {
      loggedIn.value = false
      return
    }
    const data = await res.json()
    if (!res.ok) throw new Error(data.error || 'Failed to load logs')
    loggedIn.value = true
    logs.value = data.logs
    projects.value = data.projects
  } catch (e) {
    error.value = e.message
  } finally {
    loading.value = false
  }
}

async function login() {
  error.value = ''
  loading.value = true

  try {
    const res = await fetch('/api/dashboard', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({
        action: 'login',
        username: username.value,
        password: password.value,
      }),
    })

    if (!res.ok) {
      let message = 'Login failed'

      try {
        const data = await res.json()
        message = data.error || message
      } catch {
        // Response wasn't JSON
      }

      throw new Error(message)
    }

    // Login endpoint returns 204 No Content on success.
    password.value = ''
    await loadLogs()
  } catch (e) {
    error.value = e.message
  } finally {
    loading.value = false
  }
}

async function logout() {
  await fetch('/api/dashboard', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({ action: 'logout' }),
  })
  loggedIn.value = false
  logs.value = []
}

onMounted(loadLogs)
</script>

<template>
  <main class="page">
    <section v-if="!loggedIn" class="login-card">
      <div class="brand">Logger</div>
      <h1>Private dashboard</h1>
      <p>Authorized access only.</p>
      <form @submit.prevent="login">
        <input v-model="username" autocomplete="username" placeholder="Username" />
        <input v-model="password" autocomplete="current-password" type="password" placeholder="Password" />
        <button :disabled="loading">{{ loading ? 'Checking…' : 'Sign in' }}</button>
      </form>
      <div v-if="error" class="error">{{ error }}</div>
    </section>

    <section v-else class="dashboard">
      <header class="topbar">
        <div>
          <div class="brand">Logger</div>
          <h1>Security events</h1>
        </div>
        <button class="secondary" @click="logout">Sign out</button>
      </header>

      <div class="filters">
        <select v-model="selectedProject">
          <option value="all">All projects</option>
          <option v-for="project in projects" :key="project" :value="project">{{ project }}</option>
        </select>
        <select v-model="selectedEvent">
          <option value="all">All events</option>
          <option v-for="event in eventTypes" :key="event" :value="event">{{ event }}</option>
        </select>
        <input v-model="ipSearch" placeholder="Filter IP…" />
        <button class="secondary" @click="loadLogs">Refresh</button>
      </div>

      <div v-if="error" class="error">{{ error }}</div>
      <div class="meta">{{ filteredLogs.length }} events shown · 30-day retention</div>

      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Project</th>
              <th>Event</th>
              <th>IP</th>
              <th>Result</th>
              <th>User-Agent</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="log in filteredLogs" :key="log.id">
              <td>{{ formatDate(log.created_at) }}</td>
              <td>{{ log.project }}</td>
              <td><code>{{ log.event }}</code></td>
              <td><code>{{ log.ip || 'unknown' }}</code></td>
              <td>
                <span v-if="log.success === true" class="ok">SUCCESS</span>
                <span v-else-if="log.success === false" class="bad">FAILED</span>
                <span v-else>—</span>
              </td>
              <td class="ua">{{ log.user_agent || '—' }}</td>
            </tr>
            <tr v-if="!filteredLogs.length">
              <td colspan="6" class="empty">No events found.</td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>
  </main>
</template>
