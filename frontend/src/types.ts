export type EntityType =
  | 'user'
  | 'host'
  | 'ip'
  | 'domain'
  | 'file_hash'
  | 'process'
  | 'url'
  | 'email'
  | 'cve'

export type TenantContext = {
  account_id: string
  tenant_id: string | null
  tenant_slug: string | null
  email: string
  role: string
  scope: string
}

export type LoginResponse = {
  access_token: string
  token_type: string
  expires_in: number
  context: TenantContext
}

export type Entity = {
  id: string
  tenant_id: string
  entity_type: EntityType | string
  value: string
  first_seen: string | null
  last_seen: string | null
  source: string | null
  properties: Record<string, unknown>
}

export type EntityTypeCount = {
  entity_type: EntityType | string
  count: number
}

export type Relationship = {
  id: string
  tenant_id: string
  relationship_type: string
  from_id: string
  to_id: string
  first_seen: string | null
  last_seen: string | null
  count: number
  sample_evidence_refs: string[]
}

export type Evidence = {
  event_id: string
  time: string | null
  class_uid: number | null
  class_name: string | null
  activity_id: number | null
  activity_name: string | null
  source_name: string | null
  field_path: string | null
  value: string | null
  relationship_id: string | null
}

export type GraphNode = {
  id: string
  labels: string[]
  properties: Record<string, unknown>
}

export type GraphEdge = {
  id: string
  type: string
  start_id: string
  end_id: string
  properties: Record<string, unknown>
}

export type GraphResponse = {
  nodes: GraphNode[]
  edges: GraphEdge[]
}

export type IngestFileResponse = {
  batch_id: number
  source_name: string
  parser_id: string | null
  status: string
  total_records: number
  normalized_records: number
  error_records: number
}

export type ParserSummary = {
  id: string
  display_name: string
  category: string
  description: string | null
}

export type ParserPreviewResponse = {
  parser_id: string | null
  ocsf_event: Record<string, unknown>
}

export type NormalizedEvent = {
  id: number
  batch_id: number
  event_id: string
  event_type: string
  source: string
  normalized_event: Record<string, unknown>
  created_at: string | null
}

export type IngestErrorRecord = {
  id: number
  batch_id: number
  line_number: number
  error_type: string
  message: string
  raw_line: string | null
}

export type AuditLog = {
  id: number
  tenant_id: string | null
  action: string
  actor: string
  target_type: string
  target_id: string | null
  metadata_json: Record<string, unknown>
  created_at: string
}

export const ENTITY_TYPES: EntityType[] = [
  'user',
  'host',
  'ip',
  'domain',
  'file_hash',
  'process',
  'url',
  'email',
  'cve',
]
