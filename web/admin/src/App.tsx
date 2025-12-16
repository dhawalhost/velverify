import { ChangeEvent, FormEvent, useCallback, useEffect, useMemo, useState } from 'react'
import './App.css'

const DEFAULT_BASE_URL = import.meta.env.VITE_GOVSVC_URL || 'http://localhost:8082'

interface OAuthClient {
  client_id: string
  tenant_id: string
  client_type: 'public' | 'confidential'
  name: string
  description?: string
  redirect_uris: string[]
  allowed_scopes: string[]
}

interface ClientListResponse {
  clients: OAuthClient[]
}

interface CreateClientPayload {
  client_id: string
  name: string
  client_type: 'public' | 'confidential'
  redirect_uris: string
  allowed_scopes: string
  client_secret?: string
}

const initialForm: CreateClientPayload = {
  client_id: '',
  name: '',
  client_type: 'public',
  redirect_uris: '',
  allowed_scopes: '',
}

function App() {
  const [tenantID, setTenantID] = useState('11111111-1111-1111-1111-111111111111')
  const [baseURL, setBaseURL] = useState(() => DEFAULT_BASE_URL)
  const [clients, setClients] = useState<OAuthClient[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [form, setForm] = useState<CreateClientPayload>(initialForm)
  const [secret, setSecret] = useState('')

  const resolveBaseURL = useCallback(() => {
    const fallback = typeof window !== 'undefined' && window.location?.origin ? window.location.origin : ''
    let candidate = baseURL.trim()
    if (!candidate) {
      candidate = fallback || DEFAULT_BASE_URL
    }
    if (candidate.startsWith('/')) {
      if (!fallback) {
        throw new Error('Unable to resolve relative base URL outside the browser')
      }
      candidate = `${fallback}${candidate}`
    }
    if (!/^https?:\/\//i.test(candidate)) {
      candidate = `http://${candidate}`
    }
    const parsed = new URL(candidate)
    const pathname = parsed.pathname.replace(/\/$/, '')
    return `${parsed.origin}${pathname}`
  }, [baseURL])

  const fetchClients = useCallback(async () => {
    if (!tenantID) {
      setError('Tenant ID is required')
      return
    }
    let apiBase: string
    try {
      apiBase = resolveBaseURL()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Invalid base URL')
      return
    }
    setLoading(true)
    setError(null)
    try {
      const response = await fetch(`${apiBase}/api/v1/oauth/clients`, {
        headers: {
          'X-Tenant-ID': tenantID,
        },
      })
      if (!response.ok) {
        const body = await response.json().catch(() => ({}))
        throw new Error(body.error || response.statusText)
      }
      const json = (await response.json()) as ClientListResponse
      setClients(json.clients)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch clients')
    } finally {
      setLoading(false)
    }
  }, [tenantID, resolveBaseURL])

  useEffect(() => {
    fetchClients()
  }, [fetchClients])

  const canSubmit = useMemo(() => {
    return form.client_id && form.name && form.redirect_uris && form.allowed_scopes
  }, [form])

  const createClient = async (event: FormEvent) => {
    event.preventDefault()
    if (!canSubmit) return

    let apiBase: string
    try {
      apiBase = resolveBaseURL()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Invalid base URL')
      return
    }

    try {
      const payload: Record<string, unknown> = {
        client_id: form.client_id,
        name: form.name,
        client_type: form.client_type,
        redirect_uris: form.redirect_uris
          .split(',')
          .map((uri: string) => uri.trim())
          .filter(Boolean),
        allowed_scopes: form.allowed_scopes
          .split(',')
          .map((scope: string) => scope.trim())
          .filter(Boolean),
      }
      if (form.client_type === 'confidential') {
        if (!secret) {
          throw new Error('Secret is required for confidential clients')
        }
        payload.client_secret = secret
      }

  const response = await fetch(`${apiBase}/api/v1/oauth/clients`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Tenant-ID': tenantID,
        },
        body: JSON.stringify(payload),
      })
      if (!response.ok) {
        const body = await response.json().catch(() => ({}))
        throw new Error(body.error || response.statusText)
      }
      setForm(initialForm)
      setSecret('')
      fetchClients()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create client')
    }
  }

  return (
    <div className="app">
      <header>
        <h1>Governance OAuth Clients</h1>
        <div className="config">
          <label>
            Tenant ID
            <input value={tenantID} onChange={(e: ChangeEvent<HTMLInputElement>) => setTenantID(e.target.value)} />
          </label>
          <label>
            Base URL
            <input
              value={baseURL}
              onChange={(e: ChangeEvent<HTMLInputElement>) => setBaseURL(e.target.value)}
              placeholder="http://localhost:8082"
            />
          </label>
          <button onClick={fetchClients} disabled={loading}>
            Refresh
          </button>
        </div>
      </header>

      {error && <div className="error">{error}</div>}

      <section>
        <h2>Existing clients</h2>
        {loading ? (
          <p>Loading…</p>
        ) : clients.length === 0 ? (
          <p>No clients found</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Client ID</th>
                <th>Name</th>
                <th>Type</th>
                <th>Redirect URIs</th>
                <th>Scopes</th>
              </tr>
            </thead>
            <tbody>
              {clients.map((client) => (
                <tr key={client.client_id}>
                  <td>{client.client_id}</td>
                  <td>{client.name}</td>
                  <td>{client.client_type}</td>
                  <td>
                    {client.redirect_uris.map((uri) => (
                      <div key={uri}>{uri}</div>
                    ))}
                  </td>
                  <td>{client.allowed_scopes.join(', ')}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <section>
        <h2>Create client</h2>
        <form onSubmit={createClient}>
          <label>
            Client ID
            <input value={form.client_id} onChange={(e: ChangeEvent<HTMLInputElement>) => setForm({ ...form, client_id: e.target.value })} />
          </label>
          <label>
            Name
            <input value={form.name} onChange={(e: ChangeEvent<HTMLInputElement>) => setForm({ ...form, name: e.target.value })} />
          </label>
          <label>
            Client type
            <select
              value={form.client_type}
              onChange={(e: ChangeEvent<HTMLSelectElement>) =>
                setForm({ ...form, client_type: e.target.value as 'public' | 'confidential' })
              }
            >
              <option value="public">Public</option>
              <option value="confidential">Confidential</option>
            </select>
          </label>
          <label>
            Redirect URIs (comma separated)
            <input value={form.redirect_uris} onChange={(e: ChangeEvent<HTMLInputElement>) => setForm({ ...form, redirect_uris: e.target.value })} />
          </label>
          <label>
            Allowed scopes (comma separated)
            <input value={form.allowed_scopes} onChange={(e: ChangeEvent<HTMLInputElement>) => setForm({ ...form, allowed_scopes: e.target.value })} />
          </label>
          {form.client_type === 'confidential' && (
            <label>
              Client secret
              <input type="password" value={secret} onChange={(e: ChangeEvent<HTMLInputElement>) => setSecret(e.target.value)} />
            </label>
          )}
          <button type="submit" disabled={!canSubmit || loading}>
            Create client
          </button>
        </form>
      </section>
    </div>
  )
}

export default App
