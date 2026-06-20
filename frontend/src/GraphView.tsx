import cytoscape from 'cytoscape'
import { useEffect, useRef } from 'react'
import type { Core, ElementDefinition } from 'cytoscape'
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
      maxZoom: 2.2,
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
            'text-margin-y': -9,
            'text-wrap': 'ellipsis',
            'text-max-width': '110px',
            width: '38px',
          },
        },
        {
          selector: 'edge',
          style: {
            'curve-style': 'bezier',
            'line-color': '#aeb8bf',
            'target-arrow-color': '#aeb8bf',
            'target-arrow-shape': 'triangle',
            width: '1.8px',
            label: 'data(label)',
            color: '#5a6670',
            'font-size': '8px',
            'text-background-color': '#ffffff',
            'text-background-opacity': 0.86,
            'text-background-padding': '2px',
            'text-rotation': 'autorotate',
          },
        },
        {
          selector: '.selected',
          style: {
            'border-color': '#111827',
            'border-width': '4px',
            height: '46px',
            width: '46px',
          },
        },
      ],
      layout: {
        name: 'cose',
        animate: false,
        nodeRepulsion: 9000,
        idealEdgeLength: 110,
        componentSpacing: 80,
      },
    })

    const selectedNode = cy
      .nodes()
      .filter((node) => node.data('entityId') === selectedEntityId)
      .first()
    selectedNode.addClass('selected')
    cy.fit(undefined, 28)
    cyRef.current = cy

    return () => {
      cy.destroy()
      if (cyRef.current === cy) cyRef.current = null
    }
  }, [graph, selectedEntityId])

  if (!graph || graph.nodes.length === 0) {
    return <div className="graph-empty">No graph data</div>
  }

  return <div ref={containerRef} className="graph-canvas" aria-label="Entity relationship graph" />
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
