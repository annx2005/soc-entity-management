import {
  AlertTriangle,
  Activity,
  Braces,
  Building2,
  CircleDot,
  Download,
  FileText,
  FileUp,
  Filter,
  ChevronLeft,
  ChevronRight,
  KeyRound,
  LogIn,
  LogOut,
  RefreshCw,
  Search,
  Send,
  ShieldCheck,
  ScrollText,
  UserRound,
  UserRoundPlus,
} from 'lucide-react'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type { FormEvent } from 'react'
import './App.css'
import {
  clearStoredToken,
  findPath,
  getEntity,
  getGraph,
  getIngestBatch,
  getMe,
  getStoredToken,
  ingestFile,
  listAuditLogs,
  listIngestErrors,
  listEntities,
  listRelationships,
  listNormalizedEvents,
  login,
  register,
  storeToken,
} from './api'
import { GraphView } from './GraphView'
import type { GraphViewHandle } from './GraphView'
import { ENTITY_TYPES, RELATIONSHIP_TYPES } from './types'
import type {
  AuditLog,
  Entity,
  EntityType,
  GraphFilters,
  GraphLayout,
  GraphResponse,
  IngestErrorRecord,
  IngestFileResponse,
  NormalizedEvent,
  Relationship,
  TenantContext,
} from './types'

type DetailState = {
  entity: Entity | null
  relationships: Relationship[]
  graph: GraphResponse | null
  loading: boolean
  error: string | null
}

const EMPTY_DETAIL: DetailState = {
  entity: null,
  relationships: [],
  graph: null,
  loading: false,
  error: null,
}

const TYPE_LABELS: Record<string, string> = {
  user: 'User',
  host: 'Host',
  ip: 'IP',
  domain: 'Domain',
  file_hash: 'File hash',
  process: 'Process',
}

const ENTITY_PAGE_SIZE = 25

function App() {
  const [token, setToken] = useState<string | null>(() => getStoredToken())
  const [context, setContext] = useState<TenantContext | null>(null)
  const [entities, setEntities] = useState<Entity[]>([])
  const [selectedEntityId, setSelectedEntityId] = useState<string | null>(null)
  const [entityType, setEntityType] = useState<EntityType | ''>('')
  const [valueFilter, setValueFilter] = useState('')
  const [entityPage, setEntityPage] = useState(0)
  const [hasNextEntityPage, setHasNextEntityPage] = useState(false)
  const [entitiesLoading, setEntitiesLoading] = useState(false)
  const [authLoading, setAuthLoading] = useState(Boolean(token))
  const [appError, setAppError] = useState<string | null>(null)
  const [detail, setDetail] = useState<DetailState>(EMPTY_DETAIL)
  const [auditRefreshKey, setAuditRefreshKey] = useState(0)
  const [graphHops, setGraphHops] = useState(2)
  const [graphFilters, setGraphFilters] = useState<GraphFilters>({ relationshipTypes: [] })
  const [graphLayout, setGraphLayout] = useState<GraphLayout>('force-directed')

  const refreshEntities = useCallback(async () => {
    if (!token) return
    setEntitiesLoading(true)
    setAppError(null)
    try {
      const nextEntities = await listEntities(token, {
        entityType,
        value: valueFilter,
        limit: ENTITY_PAGE_SIZE + 1,
        offset: entityPage * ENTITY_PAGE_SIZE,
      })
      const visibleEntities = nextEntities.slice(0, ENTITY_PAGE_SIZE)
      setEntities(visibleEntities)
      setHasNextEntityPage(nextEntities.length > ENTITY_PAGE_SIZE)
      setSelectedEntityId((current) => (visibleEntities.some((entity) => entity.id === current) ? current : visibleEntities[0]?.id ?? null))
    } catch (error) {
      setAppError(messageFrom(error))
    } finally {
      setEntitiesLoading(false)
    }
  }, [entityPage, entityType, token, valueFilter])

  useEffect(() => {
    if (!token) {
      setAuthLoading(false)
      return
    }

    let cancelled = false
    setAuthLoading(true)
    getMe(token)
      .then((nextContext) => {
        if (!cancelled) setContext(nextContext)
      })
      .catch((error) => {
        if (!cancelled) {
          clearStoredToken()
          setToken(null)
          setContext(null)
          setAppError(messageFrom(error))
        }
      })
      .finally(() => {
        if (!cancelled) setAuthLoading(false)
      })

    return () => {
      cancelled = true
    }
  }, [token])

  useEffect(() => {
    if (context) void refreshEntities()
  }, [context, refreshEntities])

  useEffect(() => {
    if (!token || !selectedEntityId) {
      setDetail(EMPTY_DETAIL)
      return
    }

    let cancelled = false
    setDetail((current) => ({ ...current, loading: true, error: null }))
    Promise.all([
      getEntity(token, selectedEntityId),
      listRelationships(token, selectedEntityId),
      getGraph(token, selectedEntityId, graphHops, graphFilters),
    ])
      .then(([entity, relationships, graph]) => {
        if (!cancelled) setDetail({ entity, relationships, graph, loading: false, error: null })
      })
      .catch((error) => {
        if (!cancelled) setDetail({ ...EMPTY_DETAIL, loading: false, error: messageFrom(error) })
      })

    return () => {
      cancelled = true
    }
  }, [graphFilters, graphHops, selectedEntityId, token])

  const selectedEntity = detail.entity ?? entities.find((entity) => entity.id === selectedEntityId) ?? null
  const stats = useMemo(() => buildStats(entities), [entities])

  function handleLogout() {
    clearStoredToken()
    setToken(null)
    setContext(null)
    setEntities([])
    setSelectedEntityId(null)
    setDetail(EMPTY_DETAIL)
  }

  if (authLoading) {
    return (
      <main className="boot-screen">
        <Activity className="spin" size={24} />
      </main>
    )
  }

  if (!token || !context) {
    return (
      <LoginScreen
        error={appError}
        onLogin={(nextToken, nextContext) => {
          storeToken(nextToken)
          setToken(nextToken)
          setContext(nextContext)
          setAppError(null)
        }}
      />
    )
  }

  return (
    <main className="app-shell">
      <header className="topbar">
        <div>
          <div className="brand-row">
            <ShieldCheck size={22} />
            <span>SOC Entity Management</span>
          </div>
          <div className="tenant-line">
            {context.tenant_slug ?? context.scope} · {context.email} · {context.role}
          </div>
        </div>
        <button type="button" className="icon-button" onClick={handleLogout} aria-label="Log out" title="Log out">
          <LogOut size={18} />
        </button>
      </header>

      {appError ? <div className="notice error">{appError}</div> : null}

      <section className="workspace">
        <aside className="entity-pane">
          <div className="pane-head">
            <div>
              <h1>Entities</h1>
              <p>
                Page {entityPage + 1} · {entities.length} shown
              </p>
            </div>
            <button type="button" className="icon-button" onClick={() => void refreshEntities()} aria-label="Refresh entities" title="Refresh">
              <RefreshCw size={17} className={entitiesLoading ? 'spin' : ''} />
            </button>
          </div>

          <ImportDataPanel
            token={token}
            onFinished={() => {
              setAuditRefreshKey((key) => key + 1)
              if (entityPage === 0) {
                void refreshEntities()
              } else {
                setEntityPage(0)
              }
            }}
          />

          <div className="stats-grid">
            {stats.map((item) => (
              <button
                type="button"
                className={`stat-pill ${entityType === item.type ? 'active' : ''}`}
                key={item.type}
                onClick={() => {
                  setEntityPage(0)
                  setEntityType((current) => (current === item.type ? '' : item.type))
                }}
              >
                <span>{TYPE_LABELS[item.type]}</span>
                <strong>{item.count}</strong>
              </button>
            ))}
          </div>

          <form
            className="filters"
            onSubmit={(event) => {
              event.preventDefault()
              setEntityPage(0)
              void refreshEntities()
            }}
          >
            <label>
              <Filter size={15} />
              <select
                value={entityType}
                onChange={(event) => {
                  setEntityPage(0)
                  setEntityType(event.target.value as EntityType | '')
                }}
              >
                <option value="">All types</option>
                {ENTITY_TYPES.map((type) => (
                  <option value={type} key={type}>
                    {TYPE_LABELS[type]}
                  </option>
                ))}
              </select>
            </label>
            <label>
              <Search size={15} />
              <input
                value={valueFilter}
                onChange={(event) => {
                  setEntityPage(0)
                  setValueFilter(event.target.value)
                }}
                placeholder="Search value"
              />
            </label>
          </form>

          <div className="pagination-bar">
            <button
              type="button"
              className="icon-button"
              onClick={() => setEntityPage((page) => Math.max(0, page - 1))}
              disabled={entityPage === 0 || entitiesLoading}
              aria-label="Previous entity page"
              title="Previous page"
            >
              <ChevronLeft size={17} />
            </button>
            <span>{entities.length > 0 ? `${entityPage * ENTITY_PAGE_SIZE + 1}-${entityPage * ENTITY_PAGE_SIZE + entities.length}` : '0-0'}</span>
            <button
              type="button"
              className="icon-button"
              onClick={() => setEntityPage((page) => page + 1)}
              disabled={!hasNextEntityPage || entitiesLoading}
              aria-label="Next entity page"
              title="Next page"
            >
              <ChevronRight size={17} />
            </button>
          </div>

          <div className="entity-list" aria-busy={entitiesLoading}>
            {entities.map((entity) => (
              <button
                type="button"
                className={`entity-row ${entity.id === selectedEntityId ? 'selected' : ''}`}
                key={entity.id}
                onClick={() => setSelectedEntityId(entity.id)}
              >
                <span className={`type-dot ${entity.entity_type}`} />
                <span>
                  <strong>{entity.value}</strong>
                  <small>{TYPE_LABELS[entity.entity_type] ?? entity.entity_type}</small>
                </span>
                <time>{formatDate(entity.last_seen)}</time>
              </button>
            ))}
            {!entitiesLoading && entities.length === 0 ? <div className="empty-state">No entities found</div> : null}
          </div>
        </aside>

        <section className="detail-pane">
          <div className="detail-stack">
            {selectedEntity ? (
              <EntityDetail
                entity={selectedEntity}
                detail={detail}
                token={token}
                visibleEntities={entities}
                graphHops={graphHops}
                onGraphHopsChange={setGraphHops}
                graphFilters={graphFilters}
                onGraphFiltersChange={setGraphFilters}
                graphLayout={graphLayout}
                onGraphLayoutChange={setGraphLayout}
                onPivotEntity={setSelectedEntityId}
              />
            ) : (
              <div className="empty-detail">
                <CircleDot size={22} />
                <span>Select an entity</span>
              </div>
            )}
            <AuditLogPanel token={token} refreshKey={auditRefreshKey} />
          </div>
        </section>
      </section>
    </main>
  )
}

type LoginScreenProps = {
  error: string | null
  onLogin: (token: string, context: TenantContext) => void
}

function LoginScreen({ error, onLogin }: LoginScreenProps) {
  const [mode, setMode] = useState<'signin' | 'signup'>('signin')
  const [tenantName, setTenantName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [tenantSlug, setTenantSlug] = useState('')
  const [loading, setLoading] = useState(false)
  const [formError, setFormError] = useState<string | null>(null)

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setLoading(true)
    setFormError(null)
    try {
      const response =
        mode === 'signin'
          ? await login({
              email,
              password,
              tenant_slug: tenantSlug.trim() || undefined,
            })
          : await register({
              tenant_name: tenantName,
              tenant_slug: tenantSlug,
              email,
              password,
            })
      onLogin(response.access_token, response.context)
    } catch (submitError) {
      setFormError(messageFrom(submitError))
    } finally {
      setLoading(false)
    }
  }

  return (
    <main className="login-screen">
      <form className="login-panel" onSubmit={(event) => void handleSubmit(event)}>
        <div className="login-title">
          <ShieldCheck size={28} />
          <div>
            <h1>SOC Entity Management</h1>
            <p>{mode === 'signin' ? 'Sign in to your workspace' : 'Create your workspace'}</p>
          </div>
        </div>
        <div className="auth-switch" role="tablist" aria-label="Authentication mode">
          <button
            type="button"
            className={mode === 'signin' ? 'active' : ''}
            onClick={() => {
              setMode('signin')
              setFormError(null)
            }}
          >
            <LogIn size={15} />
            <span>Sign in</span>
          </button>
          <button
            type="button"
            className={mode === 'signup' ? 'active' : ''}
            onClick={() => {
              setMode('signup')
              setFormError(null)
            }}
          >
            <UserRoundPlus size={15} />
            <span>Sign up</span>
          </button>
        </div>
        {mode === 'signup' ? (
          <label>
            <Building2 size={16} />
            <input
              value={tenantName}
              onChange={(event) => setTenantName(event.target.value)}
              placeholder="Workspace name"
              autoComplete="organization-title"
              required
            />
          </label>
        ) : null}
        <label>
          <UserRound size={16} />
          <input value={email} onChange={(event) => setEmail(event.target.value)} placeholder="Email address" autoComplete="email" required />
        </label>
        <label>
          <KeyRound size={16} />
          <input
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            placeholder={mode === 'signin' ? 'Account password' : 'Create a password'}
            type="password"
            autoComplete={mode === 'signin' ? 'current-password' : 'new-password'}
            required
          />
        </label>
        <label>
          <Braces size={16} />
          <input
            value={tenantSlug}
            onChange={(event) => setTenantSlug(event.target.value)}
            placeholder={mode === 'signin' ? 'Workspace code' : 'Create a short workspace code'}
            autoComplete="organization"
            required={mode === 'signup'}
          />
        </label>
        <button type="submit" className="primary-button" disabled={loading}>
          {loading ? (mode === 'signin' ? 'Signing in' : 'Creating workspace') : mode === 'signin' ? 'Sign in' : 'Create workspace'}
        </button>
        <p className="helper-copy">
          {mode === 'signin'
            ? 'Enter your workspace code if your organization uses one.'
            : 'This creates a new workspace and your first admin account.'}
        </p>
        {formError || error ? <div className="notice error">{formError ?? error}</div> : null}
      </form>
    </main>
  )
}

type ImportDataPanelProps = {
  token: string
  onFinished: () => void
}

function ImportDataPanel({ token, onFinished }: ImportDataPanelProps) {
  const [filePath, setFilePath] = useState('/data/raw/fake-multitenant-wazuh.jsonl')
  const [file, setFile] = useState<File | null>(null)
  const [asyncMode, setAsyncMode] = useState(true)
  const [result, setResult] = useState<IngestFileResponse | null>(null)
  const [normalized, setNormalized] = useState<NormalizedEvent[]>([])
  const [errors, setErrors] = useState<IngestErrorRecord[]>([])
  const [loading, setLoading] = useState(false)
  const [logsLoading, setLogsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!result || !asyncMode || result.status === 'completed' || result.status === 'failed') return

    let cancelled = false
    let timer = 0

    const poll = async (attempt = 0) => {
      try {
        const nextBatch = await getIngestBatch(result.batch_id)
        if (cancelled) return
        setResult(nextBatch)

        if (nextBatch.status === 'completed' || nextBatch.status === 'failed') {
          await loadBatchPreview(nextBatch.batch_id, false)
          onFinished()
          return
        }

        if (attempt < 11) {
          timer = window.setTimeout(() => {
            void poll(attempt + 1)
          }, 1500)
        }
      } catch (pollError) {
        if (!cancelled) setError(messageFrom(pollError))
      }
    }

    timer = window.setTimeout(() => {
      void poll()
    }, 1200)

    return () => {
      cancelled = true
      window.clearTimeout(timer)
    }
  }, [asyncMode, onFinished, result])

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!file && !filePath.trim()) {
      setError('Choose a file or enter a file path.')
      return
    }

    setLoading(true)
    setError(null)
    try {
      const nextResult = await ingestFile(token, { file, filePath, asyncMode })
      setResult(nextResult)
      await loadBatchPreview(nextResult.batch_id)
      onFinished()
    } catch (submitError) {
      setError(messageFrom(submitError))
    } finally {
      setLoading(false)
    }
  }

  async function loadBatchPreview(batchId = result?.batch_id, refreshBatch = true) {
    if (!batchId) return
    setLogsLoading(true)
    setError(null)
    try {
      if (refreshBatch) {
        const nextBatch = await getIngestBatch(batchId)
        setResult(nextBatch)
      }
      const [nextNormalized, nextErrors] = await Promise.all([listNormalizedEvents(batchId), listIngestErrors(batchId)])
      setNormalized(nextNormalized)
      setErrors(nextErrors)
    } catch (previewError) {
      setError(messageFrom(previewError))
    } finally {
      setLogsLoading(false)
    }
  }

  return (
    <section className="import-panel">
      <div className="section-head">
        <div>
          <h3>Import data</h3>
          <span>{result ? `Batch ${result.batch_id} · ${result.status}` : 'JSONL log file'}</span>
        </div>
        <button
          type="button"
          className="icon-button"
          onClick={() => void loadBatchPreview()}
          aria-label="Refresh import results"
          title="Refresh import results"
          disabled={!result || logsLoading}
        >
          <RefreshCw size={15} className={logsLoading ? 'spin' : ''} />
        </button>
      </div>

      <form className="import-form" onSubmit={(event) => void handleSubmit(event)}>
        <label>
          <FileText size={15} />
          <input
            value={filePath}
            onChange={(event) => {
              setFilePath(event.target.value)
              if (event.target.value.trim()) setFile(null)
            }}
            placeholder="Path inside backend container"
          />
        </label>
        <label className="file-picker">
          <FileUp size={15} />
          <input
            type="file"
            accept=".jsonl,.json,application/json"
            onChange={(event) => {
              const nextFile = event.target.files?.[0] ?? null
              setFile(nextFile)
              if (nextFile) setFilePath('')
            }}
          />
          <span>{file ? file.name : 'Upload JSONL file'}</span>
        </label>
        <div className="import-actions">
          <label className="queue-toggle">
            <input type="checkbox" checked={asyncMode} onChange={(event) => setAsyncMode(event.target.checked)} />
            <span>Use queue</span>
          </label>
          <button type="submit" className="primary-button compact" disabled={loading}>
            {loading ? <Activity size={15} className="spin" /> : <Send size={15} />}
            <span>{asyncMode ? 'Send' : 'Import'}</span>
          </button>
        </div>
      </form>

      {result ? (
        <div className="batch-summary">
          <Metric label="Records" value={String(result.total_records)} />
          <Metric label="Ready" value={String(result.normalized_records)} />
          <Metric label="Errors" value={String(result.error_records)} />
        </div>
      ) : null}

      {error ? <div className="notice error">{error}</div> : null}

      <div className="import-preview">
        <div>
          <div className="preview-title">
            <FileText size={13} />
            <span>Ready events</span>
          </div>
          {normalized.slice(0, 3).map((event) => (
            <div className="preview-row" key={event.id}>
              <strong>{event.event_type}</strong>
              <small>{event.source}</small>
            </div>
          ))}
          {result && normalized.length === 0 && !logsLoading ? <div className="preview-empty">No events yet</div> : null}
        </div>
        <div>
          <div className="preview-title">
            <AlertTriangle size={13} />
            <span>Issues</span>
          </div>
          {errors.slice(0, 3).map((item) => (
            <div className="preview-row warning" key={item.id}>
              <strong>Line {item.line_number}</strong>
              <small>{item.message}</small>
            </div>
          ))}
          {result && errors.length === 0 && !logsLoading ? <div className="preview-empty">No issues</div> : null}
        </div>
      </div>
    </section>
  )
}

function EntityDetail({
  entity,
  detail,
  token,
  visibleEntities,
  graphHops,
  onGraphHopsChange,
  graphFilters,
  onGraphFiltersChange,
  graphLayout,
  onGraphLayoutChange,
  onPivotEntity,
}: {
  entity: Entity
  detail: DetailState
  token: string
  visibleEntities: Entity[]
  graphHops: number
  onGraphHopsChange: (hops: number) => void
  graphFilters: GraphFilters
  onGraphFiltersChange: (filters: GraphFilters) => void
  graphLayout: GraphLayout
  onGraphLayoutChange: (layout: GraphLayout) => void
  onPivotEntity: (entityId: string) => void
}) {
  const enrichment = entity.properties.enrichment
  const enrichmentRows = isRecord(enrichment) ? Object.entries(enrichment) : []
  const properties = Object.entries(entity.properties).filter(([key]) => key !== 'enrichment')
  const graphViewRef = useRef<GraphViewHandle | null>(null)
  const [visibleGraph, setVisibleGraph] = useState<GraphResponse | null>(detail.graph)
  const [focusedGraphEntityId, setFocusedGraphEntityId] = useState(entity.id)
  const [graphActionLoading, setGraphActionLoading] = useState(false)
  const [graphActionError, setGraphActionError] = useState<string | null>(null)
  const [targetId, setTargetId] = useState('')
  const [pathMaxHops, setPathMaxHops] = useState(4)
  const [pathGraph, setPathGraph] = useState<GraphResponse | null>(null)
  const [pathLoading, setPathLoading] = useState(false)
  const [pathError, setPathError] = useState<string | null>(null)
  const [pathSearched, setPathSearched] = useState(false)

  useEffect(() => {
    setTargetId('')
    setPathGraph(null)
    setPathError(null)
    setPathSearched(false)
  }, [entity.id])

  useEffect(() => {
    setVisibleGraph(detail.graph)
    setFocusedGraphEntityId(entity.id)
    setGraphActionError(null)
  }, [detail.graph, entity.id])

  const handleNodeSelect = useCallback((entityId: string) => {
    setFocusedGraphEntityId(entityId)
    setGraphActionError(null)
  }, [])

  async function handleFindPath(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const normalizedTargetId = targetId.trim()
    if (!normalizedTargetId) {
      setPathError('Enter a target entity id.')
      return
    }

    setPathLoading(true)
    setPathError(null)
    setPathSearched(true)
    try {
      setPathGraph(await findPath(token, entity.id, normalizedTargetId, pathMaxHops))
    } catch (error) {
      setPathGraph(null)
      setPathError(messageFrom(error))
    } finally {
      setPathLoading(false)
    }
  }

  async function handleExpandGraph() {
    if (!focusedGraphEntityId) return
    setGraphActionLoading(true)
    setGraphActionError(null)
    try {
      const expandedGraph = await getGraph(token, focusedGraphEntityId, 1, graphFilters)
      setVisibleGraph((current) => mergeGraphs(current ?? detail.graph, expandedGraph))
    } catch (error) {
      setGraphActionError(messageFrom(error))
    } finally {
      setGraphActionLoading(false)
    }
  }

  function handlePivotGraph() {
    if (focusedGraphEntityId) onPivotEntity(focusedGraphEntityId)
  }

  function handleExportPng() {
    const png = graphViewRef.current?.exportPng()
    if (!png) {
      setGraphActionError('No graph image is ready to export.')
      return
    }
    downloadDataUrl(png, `graph-${slugValue(entity.value)}.png`)
  }

  function handleExportJson() {
    const exportGraph = visibleGraph ?? detail.graph
    if (!exportGraph) {
      setGraphActionError('No graph data is ready to export.')
      return
    }
    downloadJson(
      {
        root_entity_id: entity.id,
        selected_entity_id: focusedGraphEntityId,
        layout: graphLayout,
        hops: graphHops,
        filters: graphFilters,
        graph: exportGraph,
      },
      `graph-${slugValue(entity.value)}.json`,
    )
  }

  function toggleRelationshipType(type: string) {
    const relationshipTypes = graphFilters.relationshipTypes.includes(type)
      ? graphFilters.relationshipTypes.filter((item) => item !== type)
      : [...graphFilters.relationshipTypes, type]
    onGraphFiltersChange({ ...graphFilters, relationshipTypes })
  }

  const currentGraph = visibleGraph ?? detail.graph
  const focusedNode = currentGraph?.nodes.find((node) => stringValue(node.properties.id) === focusedGraphEntityId)
  const focusedNodeLabel = focusedNode ? stringValue(focusedNode.properties.value) || focusedGraphEntityId : entity.value

  return (
    <div className="detail-grid">
      <section className="entity-summary">
        <div>
          <span className={`type-badge ${entity.entity_type}`}>{TYPE_LABELS[entity.entity_type] ?? entity.entity_type}</span>
          <h2>{entity.value}</h2>
          <p>{entity.id}</p>
        </div>
        <div className="summary-times">
          <Metric label="First seen" value={formatDate(entity.first_seen)} />
          <Metric label="Last seen" value={formatDate(entity.last_seen)} />
          <Metric label="Source" value={entity.source ?? '-'} />
        </div>
      </section>

      {detail.error ? <div className="notice error">{detail.error}</div> : null}

      <section className="graph-section">
        <div className="section-head">
          <div>
            <h3>Graph</h3>
            <span>
              {currentGraph?.nodes.length ?? 0} nodes - {focusedNodeLabel}
            </span>
          </div>
          <div className="graph-actions">
            <button type="button" className="icon-button" onClick={() => void handleExpandGraph()} aria-label="Expand selected node" title="Expand selected node">
              {graphActionLoading ? <Activity size={15} className="spin" /> : <RefreshCw size={15} />}
            </button>
            <button type="button" className="icon-button" onClick={handlePivotGraph} aria-label="Pivot to selected node" title="Pivot to selected node">
              <Search size={15} />
            </button>
            <button type="button" className="icon-button" onClick={handleExportPng} aria-label="Export graph as PNG" title="Export PNG">
              <Download size={15} />
            </button>
            <button type="button" className="icon-button" onClick={handleExportJson} aria-label="Export graph as JSON" title="Export JSON">
              <Braces size={15} />
            </button>
          </div>
        </div>
        <div className="graph-controls">
          <label className="hop-select">
            <Filter size={15} />
            <select value={graphHops} onChange={(event) => onGraphHopsChange(Number(event.target.value))}>
              {[1, 2, 3, 4].map((hops) => (
                <option value={hops} key={hops}>
                  {hops} hop{hops > 1 ? 's' : ''}
                </option>
              ))}
            </select>
          </label>
          <label className="layout-select">
            <Filter size={15} />
            <select value={graphLayout} onChange={(event) => onGraphLayoutChange(event.target.value as GraphLayout)}>
              <option value="force-directed">Force-directed</option>
              <option value="hierarchical">Hierarchical</option>
            </select>
          </label>
          <label className="time-filter">
            <span>From</span>
            <input
              type="datetime-local"
              value={graphFilters.fromTime ?? ''}
              onChange={(event) => onGraphFiltersChange({ ...graphFilters, fromTime: event.target.value || undefined })}
            />
          </label>
          <label className="time-filter">
            <span>To</span>
            <input
              type="datetime-local"
              value={graphFilters.toTime ?? ''}
              onChange={(event) => onGraphFiltersChange({ ...graphFilters, toTime: event.target.value || undefined })}
            />
          </label>
        </div>
        <div className="relationship-filter" aria-label="Relationship type filters">
          {RELATIONSHIP_TYPES.map((type) => (
            <button
              type="button"
              className={graphFilters.relationshipTypes.includes(type) ? 'active' : ''}
              key={type}
              onClick={() => toggleRelationshipType(type)}
            >
              {type.replaceAll('_', ' ')}
            </button>
          ))}
        </div>
        {graphActionError ? <div className="notice error">{graphActionError}</div> : null}
        <GraphView
          ref={graphViewRef}
          graph={currentGraph}
          selectedEntityId={focusedGraphEntityId}
          layout={graphLayout}
          onNodeSelect={handleNodeSelect}
        />
      </section>

      <section className="path-section panel">
        <div className="section-head">
          <div>
            <h3>Path finding</h3>
            <span>{pathGraph ? `${pathGraph.nodes.length} nodes` : 'Entity to entity'}</span>
          </div>
          {pathLoading ? <Activity size={15} className="spin" /> : null}
        </div>
        <form className="path-form" onSubmit={(event) => void handleFindPath(event)}>
          <label>
            <Search size={15} />
            <input
              value={targetId}
              onChange={(event) => setTargetId(event.target.value)}
              placeholder="Target entity id"
              list="visible-entity-targets"
            />
            <datalist id="visible-entity-targets">
              {visibleEntities
                .filter((item) => item.id !== entity.id)
                .map((item) => (
                  <option value={item.id} key={item.id}>
                    {item.value}
                  </option>
                ))}
            </datalist>
          </label>
          <label>
            <Filter size={15} />
            <select value={pathMaxHops} onChange={(event) => setPathMaxHops(Number(event.target.value))}>
              {[1, 2, 3, 4].map((hops) => (
                <option value={hops} key={hops}>
                  {hops} hop{hops > 1 ? 's' : ''}
                </option>
              ))}
            </select>
          </label>
          <button type="submit" className="primary-button compact" disabled={pathLoading}>
            <Search size={15} />
            <span>Find</span>
          </button>
        </form>
        {pathError ? <div className="notice error">{pathError}</div> : null}
        {pathGraph && pathGraph.nodes.length > 0 ? <GraphView graph={pathGraph} selectedEntityId={entity.id} /> : null}
        {pathSearched && !pathLoading && !pathError && (!pathGraph || pathGraph.nodes.length === 0) ? (
          <div className="empty-state compact">No path found</div>
        ) : null}
      </section>

      <section className="info-columns">
        <div className="panel">
          <div className="section-head">
            <h3>Enrichment</h3>
            {detail.loading ? <Activity size={15} className="spin" /> : null}
          </div>
          {enrichmentRows.length > 0 ? (
            <KeyValueList rows={enrichmentRows} />
          ) : (
            <div className="empty-state compact">{String(entity.properties.enrichment_status ?? 'No enrichment')}</div>
          )}
        </div>

        <div className="panel">
          <div className="section-head">
            <h3>Properties</h3>
            <span>{properties.length}</span>
          </div>
          {properties.length > 0 ? <KeyValueList rows={properties} /> : <div className="empty-state compact">No properties</div>}
        </div>
      </section>

      <section className="panel relationships-panel">
        <div className="section-head">
          <h3>Relationships</h3>
          <span>{detail.relationships.length}</span>
        </div>
        <div className="relationship-table">
          {detail.relationships.map((relationship) => (
            <div className="relationship-row" key={relationship.id}>
              <strong>{relationship.relationship_type.replaceAll('_', ' ')}</strong>
              <span>{relationship.from_id === entity.id ? 'outbound' : 'inbound'}</span>
              <span>{relationship.count}</span>
              <time>{formatDate(relationship.last_seen)}</time>
            </div>
          ))}
          {!detail.loading && detail.relationships.length === 0 ? <div className="empty-state compact">No relationships</div> : null}
        </div>
      </section>
    </div>
  )
}

function AuditLogPanel({ token, refreshKey }: { token: string; refreshKey: number }) {
  const [logs, setLogs] = useState<AuditLog[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const loadLogs = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      setLogs(await listAuditLogs(token, { limit: 50 }))
    } catch (loadError) {
      setError(messageFrom(loadError))
    } finally {
      setLoading(false)
    }
  }, [token])

  useEffect(() => {
    void loadLogs()
  }, [loadLogs, refreshKey])

  return (
    <section className="panel audit-panel">
      <div className="section-head">
        <div>
          <h3>Audit log</h3>
          <span>{logs.length} recent events</span>
        </div>
        <button type="button" className="icon-button" onClick={() => void loadLogs()} aria-label="Refresh audit log" title="Refresh audit log">
          {loading ? <Activity size={15} className="spin" /> : <ScrollText size={15} />}
        </button>
      </div>
      {error ? <div className="notice error">{error}</div> : null}
      <div className="audit-list">
        {logs.map((log) => (
          <div className="audit-row" key={log.id}>
            <ScrollText size={15} />
            <div>
              <strong>{formatAction(log.action)}</strong>
              <span>{formatAuditTarget(log)}</span>
              <small>{formatAuditMetadata(log.metadata_json)}</small>
            </div>
            <div>
              <span>{log.actor}</span>
              <time>{formatDate(log.created_at)}</time>
            </div>
          </div>
        ))}
        {!loading && logs.length === 0 ? <div className="empty-state compact">No audit events</div> : null}
      </div>
    </section>
  )
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="metric">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  )
}

function KeyValueList({ rows }: { rows: [string, unknown][] }) {
  return (
    <dl className="kv-list">
      {rows.map(([key, value]) => (
        <div key={key}>
          <dt>{key.replaceAll('_', ' ')}</dt>
          <dd>{formatValue(value)}</dd>
        </div>
      ))}
    </dl>
  )
}

function buildStats(entities: Entity[]) {
  return ENTITY_TYPES.map((type) => ({
    type,
    count: entities.filter((entity) => entity.entity_type === type).length,
  }))
}

function formatDate(value: string | null): string {
  if (!value) return '-'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return new Intl.DateTimeFormat(undefined, {
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  }).format(date)
}

function formatValue(value: unknown): string {
  if (value === null || value === undefined || value === '') return '-'
  if (typeof value === 'string') return value
  if (typeof value === 'number' || typeof value === 'boolean') return String(value)
  return JSON.stringify(value)
}

function mergeGraphs(base: GraphResponse | null, addition: GraphResponse): GraphResponse {
  const nodes = new Map<string, GraphResponse['nodes'][number]>()
  const edges = new Map<string, GraphResponse['edges'][number]>()
  for (const node of base?.nodes ?? []) nodes.set(node.id, node)
  for (const edge of base?.edges ?? []) edges.set(edge.id, edge)
  for (const node of addition.nodes) nodes.set(node.id, node)
  for (const edge of addition.edges) edges.set(edge.id, edge)
  return { nodes: [...nodes.values()], edges: [...edges.values()] }
}

function downloadDataUrl(url: string, filename: string) {
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  link.click()
}

function downloadJson(value: unknown, filename: string) {
  const blob = new Blob([JSON.stringify(value, null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  downloadDataUrl(url, filename)
  URL.revokeObjectURL(url)
}

function slugValue(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'entity'
}

function formatAction(action: string): string {
  return action.replaceAll('_', ' ')
}

function formatAuditTarget(log: AuditLog): string {
  return log.target_id ? `${log.target_type} · ${log.target_id}` : log.target_type
}

function formatAuditMetadata(metadata: Record<string, unknown>): string {
  const rawTenant = metadata.raw_tenant_id
  const trustedTenant = metadata.trusted_tenant_id
  if (typeof rawTenant === 'string' && typeof trustedTenant === 'string') return `${rawTenant} -> ${trustedTenant}`
  const eventId = metadata.event_id
  if (typeof eventId === 'string') return `event ${eventId}`
  const sourceName = metadata.source_name
  if (typeof sourceName === 'string') return sourceName
  return ''
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function stringValue(value: unknown): string {
  return typeof value === 'string' ? value : ''
}

function messageFrom(error: unknown): string {
  return error instanceof Error ? error.message : 'Unexpected error'
}

export default App
