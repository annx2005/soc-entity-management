import cytoscape from 'cytoscape'
import { forwardRef, useEffect, useImperativeHandle, useRef } from 'react'
import type { Core, ElementDefinition, NodeSingular } from 'cytoscape'
import { Crosshair, MoveDiagonal2 } from 'lucide-react'
import type { GraphLayout, GraphResponse } from './types'

type GraphViewProps = {
  graph: GraphResponse | null
  selectedEntityId: string | null
  layout?: GraphLayout
  onNodeSelect?: (entityId: string) => void
}

export type GraphViewHandle = {
  exportPng: () => string | null
}

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
  cloud_resource: '#6a6f25',
}

export const GraphView = forwardRef<GraphViewHandle, GraphViewProps>(function GraphView(
  { graph, selectedEntityId, layout = 'force-directed', onNodeSelect },
  ref,
) {
  const containerRef = useRef<HTMLDivElement | null>(null)
  const cyRef = useRef<Core | null>(null)

  useImperativeHandle(
    ref,
    () => ({
      exportPng: () => cyRef.current?.png({ bg: '#f7f9f8', full: false, scale: 2 }) ?? null,
    }),
    [],
  )

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
      layout: layoutOptions(layout),
    })

    cy.on('tap', 'node', (event) => {
      const entityId = stringValue((event.target as NodeSingular).data('entityId'))
      if (entityId) onNodeSelect?.(entityId)
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
  }, [graph, layout, onNodeSelect, selectedEntityId])

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
})

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

function layoutOptions(layout: GraphLayout) {
  if (layout === 'hierarchical') {
    return {
      name: 'breadthfirst',
      animate: false,
      directed: true,
      padding: 32,
      spacingFactor: 1.25,
    }
  }

  return {
    name: 'cose',
    animate: false,
    nodeRepulsion: 9000,
    idealEdgeLength: 110,
    componentSpacing: 80,
  }
}

function stringValue(value: unknown): string {
  return typeof value === 'string' ? value : ''
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
