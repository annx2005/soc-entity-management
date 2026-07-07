import cytoscape from 'cytoscape'
import { useEffect, useMemo, useRef, useState } from 'react'
import type { Core, ElementDefinition } from 'cytoscape'
import { Crosshair, Eye, EyeOff, Maximize2, Minimize2, MoveDiagonal2 } from 'lucide-react'
import type { Entity, GraphResponse } from './types'

type GraphViewProps = {
  graph: GraphResponse | null
  selectedEntityId: string | null
  selectedEntity?: Entity | null
}

type RenderableGraph = {
  graph: GraphResponse | null
  hiddenEdges: number
  hiddenNodes: number
  totalEdges: number
  totalNodes: number
}

type GraphMode = 'focused' | 'all'

const MAX_RENDER_NODES = 72
const MAX_RENDER_EDGES = 90
const MAX_PRIMARY_NEIGHBORS = 36
const MAX_SECONDARY_EDGES = 42

const TYPE_COLORS: Record<string, string> = {
  user: '#2f7d5f',
  host: '#8a5a1f',
  ip: '#1b7285',
  domain: '#7a4f9a',
  file_hash: '#9a3f43',
  process: '#4e647a',
  url: '#2d6a9f',
  email: '#b35b2e',
  cve: '#8f4b66',
}

export function GraphView({ graph, selectedEntityId, selectedEntity = null }: GraphViewProps) {
  const containerRef = useRef<HTMLDivElement | null>(null)
  const cyRef = useRef<Core | null>(null)
  const [isFullscreen, setIsFullscreen] = useState(false)
  const [graphMode, setGraphMode] = useState<GraphMode>('focused')
  const displayGraph = useMemo(
    () => (graph && graph.nodes.length > 0 ? graph : selectedEntity ? graphFromEntity(selectedEntity) : graph),
    [graph, selectedEntity],
  )
  const renderableGraph = useMemo(
    () => (graphMode === 'all' ? fullGraph(displayGraph) : limitGraph(displayGraph, selectedEntityId)),
    [displayGraph, graphMode, selectedEntityId],
  )

  useEffect(() => {
    setGraphMode('focused')
  }, [displayGraph, selectedEntityId])

  useEffect(() => {
    if (!containerRef.current) return

    const elements = toElements(renderableGraph.graph)
    cyRef.current?.destroy()

    const cy = cytoscape({
      container: containerRef.current,
      elements,
      minZoom: 0.35,
      maxZoom: 2.6,
      wheelSensitivity: 0.18,
      style: [
        {
          selector: 'node',
          style: {
            'background-color': 'data(color)',
            'border-color': 'data(borderColor)',
            'border-width': '2px',
            color: '#27313a',
            content: 'data(label)',
            'font-family': 'Inter, system-ui, sans-serif',
            'font-size': '11px',
            'font-weight': 'bold',
            height: '38px',
            label: 'data(label)',
            'overlay-opacity': 0,
            'text-background-color': '#ffffff',
            'text-background-opacity': 0.92,
            'text-background-padding': '3px',
            'text-margin-y': -12,
            'text-wrap': 'wrap',
            'text-max-width': '124px',
            'text-valign': 'bottom',
            'text-halign': 'center',
            width: '38px',
          },
        },
        {
          selector: 'edge',
          style: {
            'curve-style': 'unbundled-bezier',
            'control-point-distances': [22, -22],
            'control-point-weights': [0.35, 0.65],
            'line-color': '#aeb8bf',
            'target-arrow-color': '#aeb8bf',
            'target-arrow-shape': 'triangle',
            'line-opacity': 0.68,
            'target-arrow-fill': 'filled',
            width: '1.6px',
            label: '',
            color: '#5a6670',
            'font-size': '9px',
            'text-background-color': '#ffffff',
            'text-background-opacity': 0.86,
            'text-background-padding': '2px',
            'text-rotation': 'autorotate',
          },
        },
        {
          selector: 'edge.emphasized',
          style: {
            width: '2.2px',
            'line-opacity': 0.9,
            'target-arrow-color': '#78848d',
          },
        },
        {
          selector: 'edge.edge-selected',
          style: {
            label: 'data(label)',
            width: '2.8px',
            'line-opacity': 1,
            'line-color': '#66757f',
            'target-arrow-color': '#66757f',
            'font-weight': 'bold',
            'text-background-opacity': 0.94,
          },
        },
        {
          selector: '.selected',
          style: {
            'border-color': '#111827',
            'border-width': '4px',
            height: '46px',
            width: '46px',
            'text-wrap': 'none',
          },
        },
      ],
      layout: {
        name: 'preset',
        positions: buildPositions(renderableGraph.graph, selectedEntityId),
        fit: false,
      },
    })

    const selectedNodes = cy.nodes().filter((node) => node.data('entityId') === selectedEntityId)
    if (selectedNodes.length > 0) {
      selectedNodes.addClass('selected')
      selectedNodes.connectedEdges().addClass('emphasized')
      selectedNodes.closedNeighborhood().difference(selectedNodes).addClass('neighbor')
    }

    cy.on('tap', 'edge', (event) => {
      cy.edges().removeClass('edge-selected')
      event.target.addClass('edge-selected')
    })

    cy.on('tap', (event) => {
      if (event.target === cy) {
        cy.edges().removeClass('edge-selected')
      }
    })

    cy.fit(undefined, isFullscreen ? 72 : 56)
    cyRef.current = cy

    return () => {
      cy.destroy()
      if (cyRef.current === cy) cyRef.current = null
    }
  }, [isFullscreen, renderableGraph.graph, selectedEntityId])

  useEffect(() => {
    if (!isFullscreen) return

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setIsFullscreen(false)
    }
    const previousOverflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    window.addEventListener('keydown', handleKeyDown)

    return () => {
      document.body.style.overflow = previousOverflow
      window.removeEventListener('keydown', handleKeyDown)
    }
  }, [isFullscreen])

  useEffect(() => {
    const container = containerRef.current
    if (!container) return

    let firstFrame = 0
    let secondFrame = 0
    const resizeGraph = () => {
      window.cancelAnimationFrame(firstFrame)
      window.cancelAnimationFrame(secondFrame)
      firstFrame = window.requestAnimationFrame(() => {
        secondFrame = window.requestAnimationFrame(() => {
          const cy = cyRef.current
          if (!cy) return
          cy.resize()
          cy.fit(undefined, isFullscreen ? 72 : 56)
        })
      })
    }

    const observer = new ResizeObserver(resizeGraph)
    observer.observe(container)
    window.addEventListener('resize', resizeGraph)
    resizeGraph()

    return () => {
      observer.disconnect()
      window.removeEventListener('resize', resizeGraph)
      window.cancelAnimationFrame(firstFrame)
      window.cancelAnimationFrame(secondFrame)
    }
  }, [isFullscreen, renderableGraph.graph])

  if (!renderableGraph.graph || renderableGraph.graph.nodes.length === 0) {
    return <div className="graph-empty">No graph data</div>
  }

  const hasHiddenGraphItems = renderableGraph.hiddenNodes > 0 || renderableGraph.hiddenEdges > 0
  const hasFullGraphOption = Boolean(displayGraph && (displayGraph.nodes.length > MAX_RENDER_NODES || displayGraph.edges.length > MAX_RENDER_EDGES))

  return (
    <div className={`graph-shell ${isFullscreen ? 'fullscreen' : ''}`}>
      {hasHiddenGraphItems || graphMode === 'all' ? (
        <div className="graph-density">
          <strong>
            {graphMode === 'all' ? 'All' : 'Focus'} · {renderableGraph.graph.nodes.length}/{renderableGraph.totalNodes} nodes
          </strong>
          <span>
            {renderableGraph.graph.edges.length}/{renderableGraph.totalEdges} relationships
          </span>
        </div>
      ) : null}
      <div className="graph-toolbar">
        <button type="button" className="ghost-button graph-tool" onClick={() => cyRef.current?.fit(undefined, 56)}>
          <MoveDiagonal2 size={14} />
          <span>Fit</span>
        </button>
        <button type="button" className="ghost-button graph-tool" onClick={() => focusSelectedNode(cyRef.current, selectedEntityId)}>
          <Crosshair size={14} />
          <span>Center</span>
        </button>
        {hasFullGraphOption ? (
          <button
            type="button"
            className="ghost-button graph-tool"
            onClick={() => setGraphMode((current) => (current === 'all' ? 'focused' : 'all'))}
            aria-pressed={graphMode === 'all'}
          >
            {graphMode === 'all' ? <EyeOff size={14} /> : <Eye size={14} />}
            <span>{graphMode === 'all' ? 'Focus' : 'Show all'}</span>
          </button>
        ) : null}
        <button
          type="button"
          className="ghost-button graph-tool"
          onClick={() => setIsFullscreen((current) => !current)}
          aria-pressed={isFullscreen}
        >
          {isFullscreen ? <Minimize2 size={14} /> : <Maximize2 size={14} />}
          <span>{isFullscreen ? 'Exit' : 'Full screen'}</span>
        </button>
      </div>
      <div
        key={isFullscreen ? 'fullscreen-canvas' : 'normal-canvas'}
        ref={containerRef}
        className="graph-canvas"
        aria-label="Entity relationship graph"
      />
    </div>
  )
}

function fullGraph(graph: GraphResponse | null): RenderableGraph {
  return {
    graph,
    hiddenEdges: 0,
    hiddenNodes: 0,
    totalEdges: graph?.edges.length ?? 0,
    totalNodes: graph?.nodes.length ?? 0,
  }
}

function limitGraph(graph: GraphResponse | null, selectedEntityId: string | null): RenderableGraph {
  if (!graph) {
    return { graph, hiddenEdges: 0, hiddenNodes: 0, totalEdges: 0, totalNodes: 0 }
  }

  const totalNodes = graph.nodes.length
  const totalEdges = graph.edges.length
  if (totalNodes <= MAX_RENDER_NODES && totalEdges <= MAX_RENDER_EDGES) {
    return { graph, hiddenEdges: 0, hiddenNodes: 0, totalEdges, totalNodes }
  }

  const nodeById = new Map(graph.nodes.map((node) => [node.id, node]))
  const selectedNode =
    graph.nodes.find((node) => stringValue(node.properties.id) === selectedEntityId) ??
    graph.nodes.find((node) => node.labels.includes('Entity')) ??
    graph.nodes[0]
  const selectedNodeId = selectedNode?.id

  const visibleNodeIds = new Set<string>()
  const visibleEdgeIds = new Set<string>()

  function canAddNode(nodeId: string): boolean {
    return visibleNodeIds.has(nodeId) || visibleNodeIds.size < MAX_RENDER_NODES
  }

  function addEdge(edge: GraphResponse['edges'][number]): boolean {
    if (visibleEdgeIds.has(edge.id) || visibleEdgeIds.size >= MAX_RENDER_EDGES) return false
    if (!nodeById.has(edge.start_id) || !nodeById.has(edge.end_id)) return false
    if (!canAddNode(edge.start_id) || !canAddNode(edge.end_id)) return false
    visibleNodeIds.add(edge.start_id)
    visibleNodeIds.add(edge.end_id)
    visibleEdgeIds.add(edge.id)
    return true
  }

  if (selectedNodeId) {
    visibleNodeIds.add(selectedNodeId)
    const primaryEdges = graph.edges
      .filter((edge) => edge.start_id === selectedNodeId || edge.end_id === selectedNodeId)
      .sort(compareEdges)
    for (const edge of primaryEdges.slice(0, MAX_PRIMARY_NEIGHBORS)) addEdge(edge)

    const internalEdges = graph.edges
      .filter((edge) => visibleNodeIds.has(edge.start_id) && visibleNodeIds.has(edge.end_id))
      .sort(compareEdges)
    for (const edge of internalEdges) addEdge(edge)

    let secondaryAdded = 0
    const secondaryEdges = graph.edges
      .filter((edge) => {
        const startVisible = visibleNodeIds.has(edge.start_id)
        const endVisible = visibleNodeIds.has(edge.end_id)
        return startVisible !== endVisible
      })
      .sort(compareEdges)
    for (const edge of secondaryEdges) {
      if (secondaryAdded >= MAX_SECONDARY_EDGES) break
      if (addEdge(edge)) secondaryAdded += 1
    }
  }

  if (visibleEdgeIds.size === 0) {
    for (const edge of [...graph.edges].sort(compareEdges)) addEdge(edge)
  }

  if (visibleNodeIds.size === 0 && selectedNodeId) visibleNodeIds.add(selectedNodeId)

  const visibleNodes = graph.nodes.filter((node) => visibleNodeIds.has(node.id))
  const visibleEdges = graph.edges.filter(
    (edge) => visibleEdgeIds.has(edge.id) && visibleNodeIds.has(edge.start_id) && visibleNodeIds.has(edge.end_id),
  )

  return {
    graph: { nodes: visibleNodes, edges: visibleEdges },
    hiddenEdges: Math.max(0, totalEdges - visibleEdges.length),
    hiddenNodes: Math.max(0, totalNodes - visibleNodes.length),
    totalEdges,
    totalNodes,
  }
}

function graphFromEntity(entity: Entity): GraphResponse {
  return {
    nodes: [
      {
        id: entity.id,
        labels: ['Entity', entity.entity_type],
        properties: {
          id: entity.id,
          tenant_id: entity.tenant_id,
          entity_type: entity.entity_type,
          value: entity.value,
          first_seen: entity.first_seen,
          last_seen: entity.last_seen,
          source: entity.source,
        },
      },
    ],
    edges: [],
  }
}

function toElements(graph: GraphResponse | null): ElementDefinition[] {
  if (!graph) return []

  const nodes = graph.nodes.map((node) => {
    const entityType = stringValue(node.properties.entity_type)
    const entityId = stringValue(node.properties.id)
    const isEntity = node.labels.includes('Entity')
    return {
      data: {
        id: node.id,
        entityId,
        label: stringValue(node.properties.value) || entityId || node.id,
        color: TYPE_COLORS[entityType] ?? '#667085',
        borderColor: isEntity ? '#ffffff' : '#cbd5df',
      },
    }
  })

  const edges = graph.edges.map((edge) => ({
    data: {
      id: edge.id,
      source: edge.start_id,
      target: edge.end_id,
      label: edge.type.replaceAll('_', ' '),
    },
  }))

  return [...nodes, ...edges]
}

function stringValue(value: unknown): string {
  return typeof value === 'string' ? value : ''
}

function numberValue(value: unknown): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : 0
}

function timeValue(value: unknown): number {
  if (typeof value !== 'string') return 0
  const timestamp = Date.parse(value)
  return Number.isFinite(timestamp) ? timestamp : 0
}

function compareEdges(left: GraphResponse['edges'][number], right: GraphResponse['edges'][number]): number {
  const countDelta = numberValue(right.properties.count) - numberValue(left.properties.count)
  if (countDelta !== 0) return countDelta

  const timeDelta = timeValue(right.properties.last_seen) - timeValue(left.properties.last_seen)
  if (timeDelta !== 0) return timeDelta

  const typeDelta = right.type.localeCompare(left.type)
  if (typeDelta !== 0) return typeDelta

  return left.id.localeCompare(right.id)
}

function buildPositions(graph: GraphResponse | null, selectedEntityId: string | null): Record<string, { x: number; y: number }> {
  if (!graph || graph.nodes.length === 0) return {}

  const nodeById = new Map(graph.nodes.map((node) => [node.id, node]))
  const selectedNode =
    graph.nodes.find((node) => stringValue(node.properties.id) === selectedEntityId) ??
    graph.nodes.find((node) => node.labels.includes('Entity')) ??
    graph.nodes[0]

  const adjacency = new Map<string, Set<string>>()
  for (const node of graph.nodes) adjacency.set(node.id, new Set())
  for (const edge of graph.edges) {
    adjacency.get(edge.start_id)?.add(edge.end_id)
    adjacency.get(edge.end_id)?.add(edge.start_id)
  }

  const levelByNodeId = new Map<string, number>([[selectedNode.id, 0]])
  const queue = [selectedNode.id]

  while (queue.length > 0) {
    const current = queue.shift()
    if (!current) continue
    const nextLevel = (levelByNodeId.get(current) ?? 0) + 1
    for (const neighborId of adjacency.get(current) ?? []) {
      if (levelByNodeId.has(neighborId)) continue
      levelByNodeId.set(neighborId, nextLevel)
      queue.push(neighborId)
    }
  }

  const disconnectedLevel = Math.max(...levelByNodeId.values(), 0) + 1
  const rings = new Map<number, string[]>()
  for (const node of graph.nodes) {
    const level = levelByNodeId.get(node.id) ?? disconnectedLevel
    const ring = rings.get(level)
    if (ring) {
      ring.push(node.id)
    } else {
      rings.set(level, [node.id])
    }
  }

  for (const [level, ids] of rings) {
    if (level === 0) continue
    ids.sort((leftId, rightId) => compareNodes(nodeById.get(leftId), nodeById.get(rightId)))
  }

  const positions: Record<string, { x: number; y: number }> = {
    [selectedNode.id]: { x: 0, y: 0 },
  }

  for (const [level, ids] of [...rings.entries()].sort((left, right) => left[0] - right[0])) {
    if (level === 0) continue
    const ringSize = level === 1 ? 18 : 24
    const baseRadius = 170 + (level - 1) * 210
    chunk(ids, ringSize).forEach((ringIds, ringIndex) => {
      const radius = baseRadius + ringIndex * 118
      const count = ringIds.length
      const angleOffset = count === 1 ? Math.PI / 2 : (level + ringIndex) % 2 === 0 ? Math.PI / count : Math.PI / 2

      ringIds.forEach((id, index) => {
        const angle = angleOffset + (index * 2 * Math.PI) / Math.max(count, 1)
        positions[id] = {
          x: Math.cos(angle) * radius,
          y: Math.sin(angle) * radius,
        }
      })
    })
  }

  return positions
}

function chunk<T>(items: T[], size: number): T[][] {
  const chunks: T[][] = []
  for (let index = 0; index < items.length; index += size) {
    chunks.push(items.slice(index, index + size))
  }
  return chunks
}

function compareNodes(left: GraphResponse['nodes'][number] | undefined, right: GraphResponse['nodes'][number] | undefined): number {
  const leftType = stringValue(left?.properties.entity_type)
  const rightType = stringValue(right?.properties.entity_type)
  if (leftType !== rightType) return leftType.localeCompare(rightType)

  const leftValue = stringValue(left?.properties.value)
  const rightValue = stringValue(right?.properties.value)
  if (leftValue !== rightValue) return leftValue.localeCompare(rightValue)

  return stringValue(left?.properties.id).localeCompare(stringValue(right?.properties.id))
}

function focusSelectedNode(cy: Core | null, selectedEntityId: string | null): void {
  if (!cy) return
  const selectedNode = cy
    .nodes()
    .filter((node) => node.data('entityId') === selectedEntityId)
    .first()
  if (selectedNode.length === 0) {
    cy.fit(undefined, 48)
    return
  }
  cy.animate({
    center: { eles: selectedNode },
    zoom: Math.max(cy.zoom(), 1.1),
    duration: 220,
  })
}
