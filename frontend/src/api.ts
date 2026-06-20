import type {
  Entity,
  EntityType,
  GraphResponse,
  IngestErrorRecord,
  IngestFileResponse,
  LoginResponse,
  NormalizedEvent,
  Relationship,
  TenantContext,
} from './types'

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? ''
const TOKEN_KEY = 'soc_entity_access_token'

type LoginPayload = {
  email: string
  password: string
  tenant_slug?: string
}

type RegisterPayload = {
  tenant_name: string
  tenant_slug: string
  email: string
  password: string
}

type EntityFilters = {
  entityType?: EntityType | ''
  value?: string
  limit?: number
  offset?: number
}

export function getStoredToken(): string | null {
  return window.localStorage.getItem(TOKEN_KEY)
}

export function storeToken(token: string): void {
  window.localStorage.setItem(TOKEN_KEY, token)
}

export function clearStoredToken(): void {
  window.localStorage.removeItem(TOKEN_KEY)
}

export async function login(payload: LoginPayload): Promise<LoginResponse> {
  return request<LoginResponse>('/api/auth/login', {
    method: 'POST',
    body: JSON.stringify(payload),
  })
}

export async function register(payload: RegisterPayload): Promise<LoginResponse> {
  return request<LoginResponse>('/api/auth/register', {
    method: 'POST',
    body: JSON.stringify(payload),
  })
}

export async function getMe(token: string): Promise<TenantContext> {
  return request<TenantContext>('/api/auth/me', undefined, token)
}

export async function listEntities(token: string, filters: EntityFilters): Promise<Entity[]> {
  const params = new URLSearchParams({ limit: String(filters.limit ?? 100), offset: String(filters.offset ?? 0) })
  if (filters.entityType) params.set('entity_type', filters.entityType)
  if (filters.value?.trim()) params.set('value', filters.value.trim())
  return request<Entity[]>(`/api/entities?${params.toString()}`, undefined, token)
}

export async function getEntity(token: string, entityId: string): Promise<Entity> {
  return request<Entity>(`/api/entities/${encodeURIComponent(entityId)}`, undefined, token)
}

export async function listRelationships(token: string, entityId: string): Promise<Relationship[]> {
  return request<Relationship[]>(`/api/entities/${encodeURIComponent(entityId)}/relationships?limit=100`, undefined, token)
}

export async function getGraph(token: string, entityId: string, hops = 2): Promise<GraphResponse> {
  return request<GraphResponse>(`/api/graph/${encodeURIComponent(entityId)}?hops=${hops}&limit=200`, undefined, token)
}

export async function ingestFile(
  token: string,
  input: { file?: File | null; filePath?: string; asyncMode: boolean },
): Promise<IngestFileResponse> {
  const form = new FormData()
  if (input.file) {
    form.append('file', input.file)
  } else if (input.filePath?.trim()) {
    form.append('file_path', input.filePath.trim())
  }
  return request<IngestFileResponse>(
    input.asyncMode ? '/api/events/ingest-file-async' : '/api/events/ingest-file',
    {
      method: 'POST',
      body: form,
    },
    token,
  )
}

export async function listNormalizedEvents(batchId?: number): Promise<NormalizedEvent[]> {
  const params = new URLSearchParams({ limit: '20' })
  if (batchId) params.set('batch_id', String(batchId))
  return request<NormalizedEvent[]>(`/api/events/normalized?${params.toString()}`)
}

export async function listIngestErrors(batchId?: number): Promise<IngestErrorRecord[]> {
  const params = new URLSearchParams({ limit: '20' })
  if (batchId) params.set('batch_id', String(batchId))
  return request<IngestErrorRecord[]>(`/api/events/errors?${params.toString()}`)
}

export async function getIngestBatch(batchId: number): Promise<IngestFileResponse> {
  return request<IngestFileResponse>(`/api/events/batches/${batchId}`)
}

async function request<T>(path: string, init?: RequestInit, token?: string): Promise<T> {
  const isFormData = init?.body instanceof FormData
  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...init,
    headers: {
      ...(!isFormData ? { 'Content-Type': 'application/json' } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...init?.headers,
    },
  })

  if (!response.ok) {
    const detail = await readError(response)
    throw new Error(detail || `Request failed with ${response.status}`)
  }

  return response.json() as Promise<T>
}

async function readError(response: Response): Promise<string> {
  try {
    const body = (await response.json()) as { detail?: unknown }
    return typeof body.detail === 'string' ? body.detail : JSON.stringify(body.detail ?? body)
  } catch {
    return response.statusText
  }
}
