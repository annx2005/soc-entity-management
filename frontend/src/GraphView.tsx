import cytoscape from 'cytoscape'
import { useEffect, useRef } from 'react'
import type { Core, ElementDefinition } from 'cytoscape'
import { Crosshair, MoveDiagonal2 } from 'lucide-react'
import type { GraphResponse } from './types'

type GraphViewProps = {
  graph: GraphResponse | null
  selectedEntityId: string | null
}

const TYPE_COLORS: Record<string, string> = {
  user: '#2f7d5f',
  host: '#8a5a1f',
  ip: '#1b7285',
  domain: '#7a4f9a',
  file_hash: '#9a3f43',
  process: '#4e647a',
}

export function GraphView({ graph, selectedEntityId }: GraphViewProps) {
  const containerRef = useRef<HTMLDivElement | null>(null)
  const cyRef = useRef<Core | null>(null)

  useEffect(() => {
    if (!containerRef.current) return

    const elements = toElements(graph)
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
        positions: buildPositions(graph, selectedEntityId),
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

    cy.fit(undefined, 48)
    cyRef.current = cy

    return () => {
      cy.destroy()
      if (cyRef.current === cy) cyRef.current = null
    }
  }, [graph, selectedEntityId])

  if (!graph || graph.nodes.length === 0) {
    return <div className="graph-empty">No graph data</div>
  }

  return (
    <div className="graph-shell">
      <div className="graph-toolbar">
        <button type="button" className="ghost-button graph-tool" onClick={() => cyRef.current?.fit(undefined, 48)}>
          <MoveDiagonal2 size={14} />
          <span>Fit</span>
        </button>
        <button type="button" className="ghost-button graph-tool" onClick={() => focusSelectedNode(cyRef.current, selectedEntityId)}>
          <Crosshair size={14} />
          <span>Center</span>
        </button>
      </div>
      <div ref={containerRef} className="graph-canvas" aria-label="Entity relationship graph" />
    </div>
  )
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
    const count = ids.length
    const baseRadius = 180 + (level - 1) * 170
    const radius = Math.max(baseRadius, (count * 145) / (2 * Math.PI))
    const angleOffset = level % 2 === 0 ? Math.PI / count : Math.PI / 2

    ids.forEach((id, index) => {
      const angle = angleOffset + (index * 2 * Math.PI) / Math.max(count, 1)
      positions[id] = {
        x: Math.cos(angle) * radius,
        y: Math.sin(angle) * radius,
      }
    })
  }

  return positions
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
