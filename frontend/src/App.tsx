import {
  AlertTriangle,
  Activity,
  Braces,
  Building2,
  CircleDot,
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
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import type { FormEvent, ReactNode } from "react";
import "./App.css";
import {
  clearStoredToken,
  findPath,
  getEntity,
  getEntityTypeCounts,
  getGraph,
  getIngestBatch,
  getMe,
  getStoredToken,
  ingestFile,
  listAuditLogs,
  listIngestErrors,
  listEntities,
  listRelationshipEvidence,
  listRelationships,
  listNormalizedEvents,
  login,
  register,
  storeToken,
} from "./api";
import { GraphView } from "./GraphView";
import { ENTITY_TYPES } from "./types";
import type {
  AuditLog,
  Evidence,
  Entity,
  EntityTypeCount,
  EntityType,
  GraphResponse,
  IngestErrorRecord,
  IngestFileResponse,
  NormalizedEvent,
  Relationship,
  TenantContext,
} from "./types";

type DetailState = {
  entity: Entity | null;
  relationships: Relationship[];
  graph: GraphResponse | null;
  loading: boolean;
  error: string | null;
};

const EMPTY_DETAIL: DetailState = {
  entity: null,
  relationships: [],
  graph: null,
  loading: false,
  error: null,
};

const TYPE_LABELS: Record<string, string> = {
  user: "User",
  host: "Host",
  ip: "IP",
  domain: "Domain",
  file_hash: "File hash",
  process: "Process",
  url: "URL",
  email: "Email",
  cve: "CVE",
  cloud_resource: "Cloud resource",
};

const ENTITY_PAGE_SIZE = 25;
const AUDIT_PAGE_SIZE = 20;

function App() {
  const [token, setToken] = useState<string | null>(() => getStoredToken());
  const [context, setContext] = useState<TenantContext | null>(null);
  const [page, setPage] = useState<"entities" | "audit" | "events">(
    "entities",
  );
  const [entities, setEntities] = useState<Entity[]>([]);
  const [selectedEntityId, setSelectedEntityId] = useState<string | null>(null);
  const [entityType, setEntityType] = useState("");
  const [valueFilter, setValueFilter] = useState("");
  const [entityPage, setEntityPage] = useState(0);
  const [hasNextEntityPage, setHasNextEntityPage] = useState(false);
  const [entitiesLoading, setEntitiesLoading] = useState(false);
  const [statsLoading, setStatsLoading] = useState(false);
  const [authLoading, setAuthLoading] = useState(Boolean(token));
  const [appError, setAppError] = useState<string | null>(null);
  const [detail, setDetail] = useState<DetailState>(EMPTY_DETAIL);
  const [auditRefreshKey, setAuditRefreshKey] = useState(0);
  const [graphHops, setGraphHops] = useState(2);
  const [stats, setStats] = useState<EntityTypeCount[]>([]);

  const refreshEntities = useCallback(async () => {
    if (!token) return;
    setEntitiesLoading(true);
    setAppError(null);
    try {
      const nextEntities = await listEntities(token, {
        entityType,
        value: valueFilter,
        limit: ENTITY_PAGE_SIZE + 1,
        offset: entityPage * ENTITY_PAGE_SIZE,
      });
      const visibleEntities = nextEntities.slice(0, ENTITY_PAGE_SIZE);
      setEntities(visibleEntities);
      setHasNextEntityPage(nextEntities.length > ENTITY_PAGE_SIZE);
      setSelectedEntityId((current) =>
        visibleEntities.some((entity) => entity.id === current)
          ? current
          : (visibleEntities[0]?.id ?? null),
      );
    } catch (error) {
      setAppError(messageFrom(error));
    } finally {
      setEntitiesLoading(false);
    }
  }, [entityPage, entityType, token, valueFilter]);

  const refreshStats = useCallback(async () => {
    if (!token) return;
    setStatsLoading(true);
    try {
      setStats(await getEntityTypeCounts(token, valueFilter));
    } catch (error) {
      setAppError(messageFrom(error));
    } finally {
      setStatsLoading(false);
    }
  }, [token, valueFilter]);

  useEffect(() => {
    if (!token) {
      setAuthLoading(false);
      return;
    }

    let cancelled = false;
    setAuthLoading(true);
    getMe(token)
      .then((nextContext) => {
        if (!cancelled) setContext(nextContext);
      })
      .catch((error) => {
        if (!cancelled) {
          clearStoredToken();
          setToken(null);
          setContext(null);
          setAppError(messageFrom(error));
        }
      })
      .finally(() => {
        if (!cancelled) setAuthLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [token]);

  useEffect(() => {
    if (context) void refreshEntities();
  }, [context, refreshEntities]);

  useEffect(() => {
    if (context) void refreshStats();
  }, [context, refreshStats]);

  useEffect(() => {
    if (!token || !selectedEntityId) {
      setDetail(EMPTY_DETAIL);
      return;
    }

    let cancelled = false;
    setDetail((current) => ({ ...current, loading: true, error: null }));
    Promise.all([
      getEntity(token, selectedEntityId),
      listRelationships(token, selectedEntityId),
      getGraph(token, selectedEntityId, graphHops),
    ])
      .then(([entity, relationships, graph]) => {
        if (!cancelled)
          setDetail({
            entity,
            relationships,
            graph,
            loading: false,
            error: null,
          });
      })
      .catch((error) => {
        if (!cancelled)
          setDetail({
            ...EMPTY_DETAIL,
            loading: false,
            error: messageFrom(error),
          });
      });

    return () => {
      cancelled = true;
    };
  }, [graphHops, selectedEntityId, token]);

  const selectedEntity =
    detail.entity ??
    entities.find((entity) => entity.id === selectedEntityId) ??
    null;
  const statItems = useMemo(() => buildStats(stats), [stats]);

  function handleLogout() {
    clearStoredToken();
    setToken(null);
    setContext(null);
    setEntities([]);
    setStats([]);
    setSelectedEntityId(null);
    setDetail(EMPTY_DETAIL);
  }

  if (authLoading) {
    return (
      <main className="boot-screen">
        <Activity className="spin" size={24} />
      </main>
    );
  }

  if (!token || !context) {
    return (
      <LoginScreen
        error={appError}
        onLogin={(nextToken, nextContext) => {
          storeToken(nextToken);
          setToken(nextToken);
          setContext(nextContext);
          setAppError(null);
        }}
      />
    );
  }

  return (
    <main className="app-shell">
      <header className="topbar">
        <div className="topbar-left">
          <div>
            <div className="brand-row">
              <ShieldCheck size={22} />
              <span>SOC Entity Management</span>
            </div>
            <div className="tenant-line">
              {context.tenant_slug ?? context.scope} · {context.email} ·{" "}
              {context.role}
            </div>
          </div>
          <nav className="topbar-nav" aria-label="Primary">
            <button
              type="button"
              className={page === "entities" ? "active" : ""}
              onClick={() => setPage("entities")}
            >
              <CircleDot size={15} />
              <span>Entities</span>
            </button>
            <button
              type="button"
              className={page === "audit" ? "active" : ""}
              onClick={() => setPage("audit")}
            >
              <ScrollText size={15} />
              <span>Audit log</span>
            </button>
            <button
              type="button"
              className={page === "events" ? "active" : ""}
              onClick={() => setPage("events")}
            >
              <FileText size={15} />
              <span>Event log</span>
            </button>
          </nav>
        </div>
        <button
          type="button"
          className="icon-button"
          onClick={handleLogout}
          aria-label="Log out"
          title="Log out"
        >
          <LogOut size={18} />
        </button>
      </header>

      {appError ? <div className="notice error">{appError}</div> : null}

      {page === "entities" ? (
        <section className="workspace">
          <aside className="entity-pane">
            <div className="pane-head">
              <div>
                <h1>Entities</h1>
                <p>
                  Page {entityPage + 1} · {entities.length} shown
                </p>
              </div>
              <button
                type="button"
                className="icon-button"
                onClick={() => void refreshEntities()}
                aria-label="Refresh entities"
                title="Refresh"
              >
                <RefreshCw
                  size={17}
                  className={entitiesLoading ? "spin" : ""}
                />
              </button>
            </div>

            <ImportDataPanel
              token={token}
              onFinished={() => {
                setAuditRefreshKey((key) => key + 1);
                void refreshStats();
                if (entityPage === 0) {
                  void refreshEntities();
                } else {
                  setEntityPage(0);
                }
              }}
            />

            <div className="stats-grid">
              {statItems.map((item) => (
                <button
                  type="button"
                  className={`stat-pill ${entityType === item.type ? "active" : ""}`}
                  key={item.type}
                  onClick={() => {
                    setEntityPage(0);
                    setEntityType((current) =>
                      current === item.type ? "" : item.type,
                    );
                  }}
                >
                  <span>{TYPE_LABELS[item.type]}</span>
                  <strong>{statsLoading ? "..." : item.count}</strong>
                </button>
              ))}
            </div>

            <form
              className="filters"
              onSubmit={(event) => {
                event.preventDefault();
                setEntityPage(0);
                void refreshEntities();
              }}
            >
              <label>
                <Filter size={15} />
                <select
                  value={entityType}
                  onChange={(event) => {
                    setEntityPage(0);
                    setEntityType(event.target.value);
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
                    setEntityPage(0);
                    setValueFilter(event.target.value);
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
              <span>
                {entities.length > 0
                  ? `${entityPage * ENTITY_PAGE_SIZE + 1}-${entityPage * ENTITY_PAGE_SIZE + entities.length}`
                  : "0-0"}
              </span>
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
                  className={`entity-row ${entity.id === selectedEntityId ? "selected" : ""}`}
                  key={entity.id}
                  onClick={() => setSelectedEntityId(entity.id)}
                >
                  <span className={`type-dot ${entity.entity_type}`} />
                  <span>
                    <strong>{entity.value}</strong>
                    <small>
                      {TYPE_LABELS[entity.entity_type] ?? entity.entity_type}
                    </small>
                  </span>
                  <time>{formatDate(entity.last_seen)}</time>
                </button>
              ))}
              {!entitiesLoading && entities.length === 0 ? (
                <div className="empty-state">No entities found</div>
              ) : null}
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
                />
              ) : (
                <div className="empty-detail">
                  <CircleDot size={22} />
                  <span>Select an entity</span>
                </div>
              )}
            </div>
          </section>
        </section>
      ) : page === "audit" ? (
        <section className="audit-workspace">
          <AuditLogPage token={token} refreshKey={auditRefreshKey} />
        </section>
      ) : (
        <section className="audit-workspace">
          <EventLogPage token={token} refreshKey={auditRefreshKey} />
        </section>
      )}
    </main>
  );
}

type LoginScreenProps = {
  error: string | null;
  onLogin: (token: string, context: TenantContext) => void;
};

function LoginScreen({ error, onLogin }: LoginScreenProps) {
  const [mode, setMode] = useState<"signin" | "signup">("signin");
  const [tenantName, setTenantName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [tenantSlug, setTenantSlug] = useState("");
  const [loading, setLoading] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setLoading(true);
    setFormError(null);
    try {
      const response =
        mode === "signin"
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
            });
      onLogin(response.access_token, response.context);
    } catch (submitError) {
      setFormError(messageFrom(submitError));
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="login-screen">
      <form
        className="login-panel"
        onSubmit={(event) => void handleSubmit(event)}
      >
        <div className="login-title">
          <ShieldCheck size={28} />
          <div>
            <h1>SOC Entity Management</h1>
            <p>
              {mode === "signin"
                ? "Sign in to your workspace"
                : "Create your workspace"}
            </p>
          </div>
        </div>
        <div
          className="auth-switch"
          role="tablist"
          aria-label="Authentication mode"
        >
          <button
            type="button"
            className={mode === "signin" ? "active" : ""}
            onClick={() => {
              setMode("signin");
              setFormError(null);
            }}
          >
            <LogIn size={15} />
            <span>Sign in</span>
          </button>
          <button
            type="button"
            className={mode === "signup" ? "active" : ""}
            onClick={() => {
              setMode("signup");
              setFormError(null);
            }}
          >
            <UserRoundPlus size={15} />
            <span>Sign up</span>
          </button>
        </div>
        {mode === "signup" ? (
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
          <input
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            placeholder="Email address"
            autoComplete="email"
            required
          />
        </label>
        <label>
          <KeyRound size={16} />
          <input
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            placeholder={
              mode === "signin" ? "Account password" : "Create a password"
            }
            type="password"
            autoComplete={
              mode === "signin" ? "current-password" : "new-password"
            }
            required
          />
        </label>
        <label>
          <Braces size={16} />
          <input
            value={tenantSlug}
            onChange={(event) => setTenantSlug(event.target.value)}
            placeholder={
              mode === "signin"
                ? "Workspace code"
                : "Create a short workspace code"
            }
            autoComplete="organization"
            required={mode === "signup"}
          />
        </label>
        <button type="submit" className="primary-button" disabled={loading}>
          {loading
            ? mode === "signin"
              ? "Signing in"
              : "Creating workspace"
            : mode === "signin"
              ? "Sign in"
              : "Create workspace"}
        </button>
        <p className="helper-copy">
          {mode === "signin"
            ? "Enter your workspace code if your organization uses one."
            : "This creates a new workspace and your first admin account."}
        </p>
        {formError || error ? (
          <div className="notice error">{formError ?? error}</div>
        ) : null}
      </form>
    </main>
  );
}

type ImportDataPanelProps = {
  token: string;
  onFinished: () => void;
};

function ImportDataPanel({ token, onFinished }: ImportDataPanelProps) {

  const [file, setFile] = useState<File | null>(null);
  const [result, setResult] = useState<IngestFileResponse | null>(null);
  const [normalized, setNormalized] = useState<NormalizedEvent[]>([]);
  const [errors, setErrors] = useState<IngestErrorRecord[]>([]);
  const [loading, setLoading] = useState(false);
  const [logsLoading, setLogsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadBatchPreview = useCallback(async (
    batchId = result?.batch_id,
    refreshBatch = true,
  ) => {
    if (!batchId) return;
    setLogsLoading(true);
    setError(null);
    try {
      if (refreshBatch) {
        const nextBatch = await getIngestBatch(batchId);
        setResult(nextBatch);
      }
      const [nextNormalized, nextErrors] = await Promise.all([
        listNormalizedEvents(token, { batchId, limit: 20 }),
        listIngestErrors(batchId),
      ]);
      setNormalized(nextNormalized);
      setErrors(nextErrors);
    } catch (previewError) {
      setError(messageFrom(previewError));
    } finally {
      setLogsLoading(false);
    }
  }, [result?.batch_id, token]);

  useEffect(() => {
    if (!result || result.status === "completed" || result.status === "failed")
      return;

    let cancelled = false;
    let timer = 0;

    const poll = async (attempt = 0) => {
      try {
        const nextBatch = await getIngestBatch(result.batch_id);
        if (cancelled) return;
        setResult(nextBatch);

        if (nextBatch.status === "completed" || nextBatch.status === "failed") {
          await loadBatchPreview(nextBatch.batch_id, false);
          onFinished();
          return;
        }

        if (attempt < 11) {
          timer = window.setTimeout(() => {
            void poll(attempt + 1);
          }, 1500);
        }
      } catch (pollError) {
        if (!cancelled) setError(messageFrom(pollError));
      }
    };

    timer = window.setTimeout(() => {
      void poll();
    }, 1200);

    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [loadBatchPreview, onFinished, result]);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!file) {
      setError("Choose a file to upload.");
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const nextResult = await ingestFile(token, { file });
      setResult(nextResult);
      await loadBatchPreview(nextResult.batch_id);
      if (nextResult.status === "completed" || nextResult.status === "failed") {
        onFinished();
      }
    } catch (submitError) {
      setError(messageFrom(submitError));
    } finally {
      setLoading(false);
    }
  }

  return (
    <section className="import-panel">
      <div className="section-head">
        <div>
          <h3>Import data</h3>
          <span>
            {result
              ? `Batch ${result.batch_id} · ${result.status}`
              : "JSONL log file queued through Kafka"}
          </span>
        </div>
        <button
          type="button"
          className="icon-button"
          onClick={() => void loadBatchPreview()}
          aria-label="Refresh import results"
          title="Refresh import results"
          disabled={!result || logsLoading}
        >
          <RefreshCw size={15} className={logsLoading ? "spin" : ""} />
        </button>
      </div>

      <form
        className="import-form"
        onSubmit={(event) => void handleSubmit(event)}
      >

        <label className="file-picker">
          <FileUp size={15} />
          <input
            type="file"
            accept=".jsonl,.json,application/json"
            onChange={(event) => {
              const nextFile = event.target.files?.[0] ?? null;
              setFile(nextFile);

            }}
          />
          <span>{file ? file.name : "Upload JSONL file"}</span>
        </label>
        <div className="import-actions">
          <button
            type="submit"
            className="primary-button compact"
            disabled={loading}
          >
            {loading ? (
              <Activity size={15} className="spin" />
            ) : (
              <Send size={15} />
            )}
            <span>Import</span>
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

      {(normalized.length > 0 || errors.length > 0) ? (
        <div className="import-preview">
          {normalized.length > 0 ? (
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
            </div>
          ) : null}
          {errors.length > 0 ? (
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
            </div>
          ) : null}
        </div>
      ) : null}
    </section>
  );
}

function EntityDetail({
  entity,
  detail,
  token,
  visibleEntities,
  graphHops,
  onGraphHopsChange,
}: {
  entity: Entity;
  detail: DetailState;
  token: string;
  visibleEntities: Entity[];
  graphHops: number;
  onGraphHopsChange: (hops: number) => void;
}) {
  const enrichment = entity.properties.enrichment;
  const enrichmentRows = isRecord(enrichment)
    ? buildEnrichmentRows(entity.entity_type, enrichment)
    : [];
  const properties = Object.entries(entity.properties).filter(
    ([key]) => key !== "enrichment",
  );
  const [targetId, setTargetId] = useState("");
  const [pathMaxHops, setPathMaxHops] = useState(4);
  const [pathGraph, setPathGraph] = useState<GraphResponse | null>(null);
  const [pathLoading, setPathLoading] = useState(false);
  const [pathError, setPathError] = useState<string | null>(null);
  const [pathSearched, setPathSearched] = useState(false);
  const [expandedRelationshipId, setExpandedRelationshipId] = useState<
    string | null
  >(null);
  const [relationshipEvidence, setRelationshipEvidence] = useState<
    Record<string, Evidence[]>
  >({});
  const [relationshipEvidenceLoading, setRelationshipEvidenceLoading] =
    useState<Record<string, boolean>>({});
  const [relationshipEvidenceError, setRelationshipEvidenceError] = useState<
    Record<string, string | null>
  >({});
  const firstSeen = formatDateParts(entity.first_seen);
  const lastSeen = formatDateParts(entity.last_seen);

  useEffect(() => {
    setTargetId("");
    setPathGraph(null);
    setPathError(null);
    setPathSearched(false);
    setExpandedRelationshipId(null);
    setRelationshipEvidence({});
    setRelationshipEvidenceLoading({});
    setRelationshipEvidenceError({});
  }, [entity.id]);

  async function handleFindPath(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const normalizedTargetId = targetId.trim();
    if (!normalizedTargetId) {
      setPathError("Enter a target entity id.");
      return;
    }

    setPathLoading(true);
    setPathError(null);
    setPathSearched(true);
    try {
      setPathGraph(
        await findPath(token, entity.id, normalizedTargetId, pathMaxHops),
      );
    } catch (error) {
      setPathGraph(null);
      setPathError(messageFrom(error));
    } finally {
      setPathLoading(false);
    }
  }

  async function toggleRelationshipEvidence(relationshipId: string) {
    if (expandedRelationshipId === relationshipId) {
      setExpandedRelationshipId(null);
      return;
    }

    setExpandedRelationshipId(relationshipId);
    if (
      relationshipEvidence[relationshipId] ||
      relationshipEvidenceLoading[relationshipId]
    )
      return;

    setRelationshipEvidenceLoading((current) => ({
      ...current,
      [relationshipId]: true,
    }));
    setRelationshipEvidenceError((current) => ({
      ...current,
      [relationshipId]: null,
    }));
    try {
      const evidence = await listRelationshipEvidence(
        token,
        entity.id,
        relationshipId,
      );
      setRelationshipEvidence((current) => ({
        ...current,
        [relationshipId]: evidence,
      }));
    } catch (error) {
      setRelationshipEvidenceError((current) => ({
        ...current,
        [relationshipId]: messageFrom(error),
      }));
    } finally {
      setRelationshipEvidenceLoading((current) => ({
        ...current,
        [relationshipId]: false,
      }));
    }
  }

  return (
    <div className="detail-grid">
      <section className="entity-summary">
        <div>
          <span className={`type-badge ${entity.entity_type}`}>
            {TYPE_LABELS[entity.entity_type] ?? entity.entity_type}
          </span>
          <h2>{entity.value}</h2>
          <p>{entity.id}</p>
        </div>
        <div className="entity-metadata-row">
          <div className="meta-item">
            <span className="meta-label">First seen</span>
            <div className="meta-value">
              <strong>{firstSeen.primary}</strong>
              {firstSeen.secondary && <span className="meta-sub">{firstSeen.secondary}</span>}
            </div>
          </div>
          <div className="meta-divider" />
          <div className="meta-item">
            <span className="meta-label">Last seen</span>
            <div className="meta-value">
              <strong>{lastSeen.primary}</strong>
              {lastSeen.secondary && <span className="meta-sub">{lastSeen.secondary}</span>}
            </div>
          </div>
          <div className="meta-divider" />
          <div className="meta-item">
            <span className="meta-label">Source</span>
            <div className="meta-value">
              <strong className="mono" title={entity.source ?? "-"}>
                {entity.source ?? "-"}
              </strong>
            </div>
          </div>
        </div>
      </section>

      {detail.error ? <div className="notice error">{detail.error}</div> : null}

      <section className="graph-section">
        <div className="section-head">
          <div>
            <h3>Graph</h3>
            <span>{detail.graph?.nodes.length ?? 0} nodes</span>
          </div>
          <label className="hop-select">
            <Filter size={15} />
            <select
              value={graphHops}
              onChange={(event) =>
                onGraphHopsChange(Number(event.target.value))
              }
            >
              {[1, 2, 3, 4].map((hops) => (
                <option value={hops} key={hops}>
                  {hops} hop{hops > 1 ? "s" : ""}
                </option>
              ))}
            </select>
          </label>
        </div>
        <GraphView graph={detail.graph} selectedEntityId={entity.id} />
      </section>

      <section className="path-section panel">
        <div className="section-head">
          <div>
            <h3>Path finding</h3>
            <span>
              {pathGraph
                ? `${pathGraph.nodes.length} nodes`
                : "Entity to entity"}
            </span>
          </div>
          {pathLoading ? <Activity size={15} className="spin" /> : null}
        </div>
        <form
          className="path-form"
          onSubmit={(event) => void handleFindPath(event)}
        >
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
            <select
              value={pathMaxHops}
              onChange={(event) => setPathMaxHops(Number(event.target.value))}
            >
              {[1, 2, 3, 4].map((hops) => (
                <option value={hops} key={hops}>
                  {hops} hop{hops > 1 ? "s" : ""}
                </option>
              ))}
            </select>
          </label>
          <button
            type="submit"
            className="primary-button compact"
            disabled={pathLoading}
          >
            <Search size={15} />
            <span>Find</span>
          </button>
        </form>
        {pathError ? <div className="notice error">{pathError}</div> : null}
        {pathGraph && pathGraph.nodes.length > 0 ? (
          <GraphView graph={pathGraph} selectedEntityId={entity.id} />
        ) : null}
        {pathSearched &&
        !pathLoading &&
        !pathError &&
        (!pathGraph || pathGraph.nodes.length === 0) ? (
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
            <div className="empty-state compact">
              {String(entity.properties.enrichment_status ?? "No enrichment")}
            </div>
          )}
        </div>

        <div className="panel">
          <div className="section-head">
            <h3>Properties</h3>
            <span>{properties.length}</span>
          </div>
          {properties.length > 0 ? (
            <KeyValueList rows={properties} />
          ) : (
            <div className="empty-state compact">No properties</div>
          )}
        </div>
      </section>

      <section className="panel relationships-panel">
        <div className="section-head">
          <h3>Relationships</h3>
          <span>{detail.relationships.length}</span>
        </div>
        <div className="relationship-table">
          {detail.relationships.map((relationship) => (
            <div className="relationship-card" key={relationship.id}>
              <div className="relationship-row">
                <strong>
                  {relationship.relationship_type.replaceAll("_", " ")}
                </strong>
                <span>
                  {relationship.from_id === entity.id ? "outbound" : "inbound"}
                </span>
                <span>{relationship.count}</span>
                <time>{formatDate(relationship.last_seen)}</time>
              </div>
              <div className="relationship-meta">
                <span>
                  {relationship.sample_evidence_refs.length} sample evidence
                  refs
                </span>
                <button
                  type="button"
                  className="ghost-button"
                  onClick={() =>
                    void toggleRelationshipEvidence(relationship.id)
                  }
                >
                  {expandedRelationshipId === relationship.id
                    ? "Hide evidence"
                    : "View evidence"}
                </button>
              </div>
              {expandedRelationshipId === relationship.id ? (
                <div className="relationship-evidence">
                  {relationshipEvidenceError[relationship.id] ? (
                    <div className="notice error">
                      {relationshipEvidenceError[relationship.id]}
                    </div>
                  ) : null}
                  {relationshipEvidenceLoading[relationship.id] ? (
                    <div className="empty-state compact">Loading evidence</div>
                  ) : (
                    <>
                      {(relationshipEvidence[relationship.id] ?? []).map(
                        (evidence) => (
                          <div
                            className="evidence-row"
                            key={`${relationship.id}:${evidence.event_id}`}
                          >
                            <strong>{evidence.event_id}</strong>
                            <span>{formatEvidenceLabel(evidence)}</span>
                            <small>{evidence.source_name ?? "-"}</small>
                            <time>{formatDate(evidence.time)}</time>
                          </div>
                        ),
                      )}
                      {!relationshipEvidenceError[relationship.id] &&
                      (relationshipEvidence[relationship.id] ?? []).length ===
                        0 ? (
                        <div className="empty-state compact">
                          No evidence found
                        </div>
                      ) : null}
                    </>
                  )}
                </div>
              ) : null}
            </div>
          ))}
          {!detail.loading && detail.relationships.length === 0 ? (
            <div className="empty-state compact">No relationships</div>
          ) : null}
        </div>
      </section>
    </div>
  );
}

function AuditLogPage({
  token,
  refreshKey,
}: {
  token: string;
  refreshKey: number;
}) {
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [page, setPage] = useState(0);
  const [hasNextPage, setHasNextPage] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadLogs = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const nextLogs = await listAuditLogs(token, {
        limit: AUDIT_PAGE_SIZE + 1,
        offset: page * AUDIT_PAGE_SIZE,
      });
      setLogs(nextLogs.slice(0, AUDIT_PAGE_SIZE));
      setHasNextPage(nextLogs.length > AUDIT_PAGE_SIZE);
    } catch (loadError) {
      setError(messageFrom(loadError));
    } finally {
      setLoading(false);
    }
  }, [page, token]);

  useEffect(() => {
    void loadLogs();
  }, [loadLogs, refreshKey]);

  return (
    <section className="audit-page panel">
      <div className="audit-page-head">
        <div>
          <h1>Audit log</h1>
          <p>
            Page {page + 1} · {logs.length} shown
          </p>
        </div>
        <button
          type="button"
          className="icon-button"
          onClick={() => void loadLogs()}
          aria-label="Refresh audit log"
          title="Refresh audit log"
        >
          {loading ? (
            <Activity size={15} className="spin" />
          ) : (
            <ScrollText size={15} />
          )}
        </button>
      </div>
      {error ? <div className="notice error">{error}</div> : null}
      <div className="pagination-bar audit-pagination">
        <button
          type="button"
          className="icon-button"
          onClick={() => setPage((current) => Math.max(0, current - 1))}
          disabled={page === 0 || loading}
          aria-label="Previous audit page"
          title="Previous page"
        >
          <ChevronLeft size={17} />
        </button>
        <span>
          {logs.length > 0
            ? `${page * AUDIT_PAGE_SIZE + 1}-${page * AUDIT_PAGE_SIZE + logs.length}`
            : "0-0"}
        </span>
        <button
          type="button"
          className="icon-button"
          onClick={() => setPage((current) => current + 1)}
          disabled={!hasNextPage || loading}
          aria-label="Next audit page"
          title="Next page"
        >
          <ChevronRight size={17} />
        </button>
      </div>
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
        {!loading && logs.length === 0 ? (
          <div className="empty-state compact">No audit events</div>
        ) : null}
      </div>
    </section>
  );
}

function EventLogPage({
  token,
  refreshKey,
}: {
  token: string;
  refreshKey: number;
}) {
  const [events, setEvents] = useState<NormalizedEvent[]>([]);
  const [page, setPage] = useState(0);
  const [hasNextPage, setHasNextPage] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadEvents = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const nextEvents = await listNormalizedEvents(token, {
        limit: AUDIT_PAGE_SIZE + 1,
        offset: page * AUDIT_PAGE_SIZE,
      });
      setEvents(nextEvents.slice(0, AUDIT_PAGE_SIZE));
      setHasNextPage(nextEvents.length > AUDIT_PAGE_SIZE);
    } catch (loadError) {
      setError(messageFrom(loadError));
    } finally {
      setLoading(false);
    }
  }, [page, token]);

  useEffect(() => {
    void loadEvents();
  }, [loadEvents, refreshKey]);

  return (
    <section className="audit-page panel">
      <div className="audit-page-head">
        <div>
          <h1>Event log</h1>
          <p>
            Most recent processed events first · Page {page + 1} ·{" "}
            {events.length} shown
          </p>
        </div>
        <button
          type="button"
          className="icon-button"
          onClick={() => void loadEvents()}
          aria-label="Refresh event log"
          title="Refresh event log"
        >
          {loading ? (
            <Activity size={15} className="spin" />
          ) : (
            <FileText size={15} />
          )}
        </button>
      </div>
      {error ? <div className="notice error">{error}</div> : null}
      <div className="pagination-bar audit-pagination">
        <button
          type="button"
          className="icon-button"
          onClick={() => setPage((current) => Math.max(0, current - 1))}
          disabled={page === 0 || loading}
          aria-label="Previous event page"
          title="Previous page"
        >
          <ChevronLeft size={17} />
        </button>
        <span>
          {events.length > 0
            ? `${page * AUDIT_PAGE_SIZE + 1}-${page * AUDIT_PAGE_SIZE + events.length}`
            : "0-0"}
        </span>
        <button
          type="button"
          className="icon-button"
          onClick={() => setPage((current) => current + 1)}
          disabled={!hasNextPage || loading}
          aria-label="Next event page"
          title="Next page"
        >
          <ChevronRight size={17} />
        </button>
      </div>
      <div className="event-log-list">
        {events.map((event) => {
          const facts = buildNormalizedEventFacts(event);

          return (
            <article className="event-log-card" key={event.id}>
              <div className="event-log-head">
                <div>
                  <strong>{formatNormalizedEventTitle(event)}</strong>
                  <span>{formatNormalizedEventSubtitle(event)}</span>
                </div>
                <time>{formatDate(event.created_at)}</time>
              </div>
              <div
                className="event-log-meta"
                style={{ gridTemplateColumns: `repeat(${facts.length}, minmax(148px, 1fr))` }}
              >
                {facts.map(([label, value]) => (
                  <div className="event-log-fact" key={`${event.id}:${label}`}>
                    <span>{label}</span>
                    <strong>{value}</strong>
                  </div>
                ))}
              </div>
              <details className="event-log-raw">
                <summary>Raw normalized event</summary>
                <pre>{JSON.stringify(event.normalized_event, null, 2)}</pre>
              </details>
            </article>
          );
        })}
        {!loading && events.length === 0 ? (
          <div className="empty-state compact">No processed events</div>
        ) : null}
      </div>
    </section>
  );
}

function Metric({
  label,
  value,
  secondary,
  icon,
  mono = false,
}: {
  label: string;
  value: string;
  secondary?: string;
  icon?: ReactNode;
  mono?: boolean;
}) {
  return (
    <div className="metric">
      {icon ? <div className="metric-icon">{icon}</div> : null}
      <div className="metric-copy">
        <span>{label}</span>
        <strong className={mono ? "metric-value-mono" : undefined}>{value}</strong>
        {secondary ? <small>{secondary}</small> : null}
      </div>
    </div>
  );
}

function KeyValueList({ rows }: { rows: [string, unknown][] }) {
  return (
    <dl className="kv-list">
      {rows.map(([key, value]) => (
        <div key={key}>
          <dt>{formatFieldLabel(key)}</dt>
          <dd>{formatValue(value)}</dd>
        </div>
      ))}
    </dl>
  );
}

function buildStats(entityTypeCounts: EntityTypeCount[]) {
  const countsByType = new Map(
    entityTypeCounts.map((item) => [item.entity_type, item.count]),
  );
  const extraTypes = entityTypeCounts
    .map((item) => item.entity_type)
    .filter((type) => !ENTITY_TYPES.includes(type as EntityType))
    .sort((left, right) => String(left).localeCompare(String(right)));

  return [...ENTITY_TYPES, ...extraTypes].map((type) => ({
    type,
    count: countsByType.get(type) ?? 0,
  }));
}

function formatDate(value: string | null): string {
  const { primary, secondary } = formatDateParts(value);
  return secondary ? `${primary}, ${secondary}` : primary;
}

function formatDateParts(
  value: string | null,
): { primary: string; secondary?: string } {
  if (!value) return { primary: "-" };
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return { primary: value };
  return {
    primary: new Intl.DateTimeFormat(undefined, {
      month: "short",
      day: "2-digit",
    }).format(date),
    secondary: new Intl.DateTimeFormat(undefined, {
      hour: "2-digit",
      minute: "2-digit",
    }).format(date),
  };
}

function formatValue(value: unknown): string {
  if (value === null || value === undefined || value === "") return "-";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean")
    return String(value);
  if (Array.isArray(value))
    return value.length > 0 ? value.map((item) => formatValue(item)).join(", ") : "-";
  return JSON.stringify(value);
}

function buildEnrichmentRows(
  entityType: EntityType | string,
  enrichment: Record<string, unknown>,
): [string, unknown][] {
  const prioritiesByType: Record<string, string[]> = {
    ip: [
      "country",
      "country_code",
      "continent",
      "continent_code",
      "asn",
      "as_name",
      "as_domain",
      "reputation",
      "classification",
      "noise",
      "riot",
      "last_seen",
      "source",
      "cache_status",
    ],
    file_hash: [
      "malware_family",
      "signature",
      "file_name",
      "file_type",
      "file_type_mime",
      "file_format",
      "tags",
      "delivery_method",
      "reporter",
      "origin_country",
      "first_seen",
      "last_seen",
      "source",
      "cache_status",
      "sha256_hash",
      "sha1_hash",
      "md5_hash",
    ],
  };

  const priority = prioritiesByType[entityType] ?? ["source", "cache_status"];
  const prioritySet = new Set(priority);
  const orderedKeys = [
    ...priority.filter((key) => hasDisplayValue(enrichment[key])),
    ...Object.keys(enrichment)
      .filter((key) => !prioritySet.has(key) && hasDisplayValue(enrichment[key]))
      .sort((left, right) => formatFieldLabel(left).localeCompare(formatFieldLabel(right))),
  ];

  return orderedKeys.map((key) => [key, enrichment[key]]);
}

function formatFieldLabel(key: string): string {
  const labels: Record<string, string> = {
    as_domain: "AS domain",
    as_name: "AS name",
    asn: "ASN",
    cache_status: "Cache status",
    continent_code: "Continent code",
    country_code: "Country code",
    file_format: "File format",
    file_name: "File name",
    file_size: "File size",
    file_type: "File type",
    file_type_mime: "MIME type",
    first_seen: "First seen",
    last_seen: "Last seen",
    malware_family: "Malware family",
    md5_hash: "MD5",
    origin_country: "Origin country",
    sha1_hash: "SHA1",
    sha256_hash: "SHA256",
    source_name: "Source name",
    source_field: "Source field",
    ssdeep: "SSDEEP",
    tlsh: "TLSH",
  };
  return labels[key] ?? key.replaceAll("_", " ");
}

function hasDisplayValue(value: unknown): boolean {
  if (value === null || value === undefined || value === "") return false;
  if (Array.isArray(value)) return value.length > 0;
  if (typeof value === "object") return !isRecord(value) || Object.keys(value).length > 0;
  return true;
}

function formatAction(action: string): string {
  return action.replaceAll("_", " ");
}

function formatAuditTarget(log: AuditLog): string {
  return log.target_id
    ? `${log.target_type} · ${log.target_id}`
    : log.target_type;
}

function formatAuditMetadata(metadata: Record<string, unknown>): string {
  const rawTenant = metadata.raw_tenant_id;
  const trustedTenant = metadata.trusted_tenant_id;
  if (typeof rawTenant === "string" && typeof trustedTenant === "string")
    return `${rawTenant} -> ${trustedTenant}`;
  const eventId = metadata.event_id;
  if (typeof eventId === "string") return `event ${eventId}`;
  const sourceName = metadata.source_name;
  if (typeof sourceName === "string") return sourceName;
  return "";
}

function formatEvidenceLabel(evidence: Evidence): string {
  const parts = [evidence.class_name, evidence.activity_name].filter(
    (value): value is string => Boolean(value),
  );
  return parts.length > 0 ? parts.join(" · ") : "Event evidence";
}

function formatNormalizedEventTitle(event: NormalizedEvent): string {
  const payload = event.normalized_event;
  const finding = recordValue(payload.finding);
  const process = recordValue(payload.process);
  const actor = recordValue(payload.actor);
  const actorUser = recordValue(actor?.user);
  const file = recordValue(payload.file);
  const query = recordValue(payload.query);
  const device = recordValue(payload.device);

  const findingTitle = stringFrom(finding?.title);
  if (findingTitle) return findingTitle;

  switch (event.event_type) {
    case "windows_logon_success":
      return `${stringFrom(actorUser?.name) || "User"} logged on to ${stringFrom(device?.hostname) || "host"}`;
    case "windows_logon_failure":
      return `${stringFrom(actorUser?.name) || "User"} failed logon on ${stringFrom(device?.hostname) || "host"}`;
    case "process_execution":
      return `${stringFrom(process?.name) || stringFrom(file?.name) || "Process"} executed`;
    case "dns_query":
      return `DNS query for ${stringFrom(query?.hostname) || "unknown host"}`;
    case "network_connection":
      return `${stringFrom(device?.hostname) || "Host"} network connection`;
    default:
      return formatAction(event.event_type);
  }
}

function formatNormalizedEventSubtitle(event: NormalizedEvent): string {
  const payload = event.normalized_event;
  const parts = [
    stringFrom(payload.class_name),
    stringFrom(payload.activity_name),
    event.source,
    event.event_id,
  ].filter((value): value is string => Boolean(value));
  return parts.join(" · ");
}

function buildNormalizedEventFacts(event: NormalizedEvent): [string, string][] {
  const payload = event.normalized_event;
  const device = recordValue(payload.device);
  const actor = recordValue(payload.actor);
  const actorUser = recordValue(actor?.user);
  const process = recordValue(payload.process);
  const file = recordValue(payload.file);
  const query = recordValue(payload.query);
  const finding = recordValue(payload.finding);

  const facts: [string, string | null][] = [
    ["Event time", formatEpochMillis(payload.time)],
    ["Host", stringFrom(device?.hostname)],
    ["User", stringFrom(actorUser?.name)],
    ["Process", stringFrom(process?.name) || stringFrom(file?.name)],
    ["Query", stringFrom(query?.hostname)],
    ["Severity", severityLabel(finding?.severity_id)],
    ["MITRE", joinArray(finding?.mitre_ids)],
    ["Source", event.source],
  ];

  return facts.reduce<[string, string][]>((rows, [label, value]) => {
    if (value) rows.push([label, value]);
    return rows;
  }, []);
}

function formatEpochMillis(value: unknown): string | null {
  if (typeof value !== "number" || !Number.isFinite(value)) return null;
  return formatDate(new Date(value).toISOString());
}

function severityLabel(value: unknown): string | null {
  if (typeof value !== "number" || !Number.isFinite(value)) return null;
  return `P${value}`;
}

function recordValue(value: unknown): Record<string, unknown> | null {
  return isRecord(value) ? value : null;
}

function stringFrom(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value : null;
}

function joinArray(value: unknown): string | null {
  if (!Array.isArray(value)) return null;
  const items = value.filter(
    (item): item is string => typeof item === "string" && Boolean(item.trim()),
  );
  return items.length > 0 ? items.join(", ") : null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function messageFrom(error: unknown): string {
  return error instanceof Error ? error.message : "Unexpected error";
}

export default App;
