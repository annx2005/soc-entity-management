import type {
  AuditLog,
  Evidence,
  Entity,
  EntityTypeCount,
  EntityType,
  GraphResponse,
  IngestErrorRecord,
  IngestFileResponse,
  LoginResponse,
  NormalizedEvent,
  Relationship,
  TenantContext,
} from './types'

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL
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

type AuditLogFilters = {
  limit?: number
  offset?: number
  action?: string
  targetType?: string
  targetId?: string
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

export async function getEntityTypeCounts(token: string, value?: string): Promise<EntityTypeCount[]> {
  const params = new URLSearchParams()
  if (value?.trim()) params.set('value', value.trim())
  const suffix = params.size > 0 ? `?${params.toString()}` : ''
  return request<EntityTypeCount[]>(`/api/entities/stats${suffix}`, undefined, token)
}

export async function getEntity(token: string, entityId: string): Promise<Entity> {
  return request<Entity>(`/api/entities/${encodeURIComponent(entityId)}`, undefined, token)
}

export async function listRelationships(token: string, entityId: string): Promise<Relationship[]> {
  return request<Relationship[]>(`/api/entities/${encodeURIComponent(entityId)}/relationships?limit=100`, undefined, token)
}

export async function listRelationshipEvidence(token: string, entityId: string, relationshipId: string): Promise<Evidence[]> {
  return request<Evidence[]>(
    `/api/entities/${encodeURIComponent(entityId)}/relationships/${encodeURIComponent(relationshipId)}/evidence?limit=20`,
    undefined,
    token,
  )
}

export async function getGraph(token: string, entityId: string, hops = 2): Promise<GraphResponse> {
  return request<GraphResponse>(`/api/graph/${encodeURIComponent(entityId)}?hops=${hops}&limit=200`, undefined, token)
}

export async function findPath(token: string, sourceId: string, targetId: string, maxHops = 4): Promise<GraphResponse> {
  const params = new URLSearchParams({
    source_id: sourceId,
    target_id: targetId,
    max_hops: String(maxHops),
    limit: '50',
  })
  return request<GraphResponse>(`/api/graph/path?${params.toString()}`, undefined, token)
}

export async function ingestFile(
  token: string,
  input: { file?: File | null; filePath?: string },
): Promise<IngestFileResponse> {
  const form = new FormData()
  if (input.file) {
    form.append('file', input.file)
  } else if (input.filePath?.trim()) {
    form.append('file_path', input.filePath.trim())
  }
  return request<IngestFileResponse>(
    '/api/events/ingest-file-async',
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

export async function listAuditLogs(token: string, filters: AuditLogFilters = {}): Promise<AuditLog[]> {
  const params = new URLSearchParams({ limit: String(filters.limit ?? 50), offset: String(filters.offset ?? 0) })
  if (filters.action?.trim()) params.set('action', filters.action.trim())
  if (filters.targetType?.trim()) params.set('target_type', filters.targetType.trim())
  if (filters.targetId?.trim()) params.set('target_id', filters.targetId.trim())
  return request<AuditLog[]>(`/api/audit-logs?${params.toString()}`, undefined, token)
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
