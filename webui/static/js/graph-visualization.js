class GraphVisualization {
    constructor(containerId) {
        this.containerId = containerId;
        this.cy = null;
        this.currentJobId = null;
        this.graphData = null;
        this.filters = {
            minComplexity: 0,
            maxComplexity: 100,
            searchQuery: '',
            showOnlyCritical: false
        };
        
        this.initialize();
    }
    
    initialize() {
        const container = document.getElementById(this.containerId);
        if (!container) {
            console.error(`Container ${this.containerId} not found`);
            return;
        }
        
        this.cy = cytoscape({
            container: container,
            style: [
                {
                    selector: 'node',
                    style: {
                        'background-color': '#666',
                        'label': 'data(label)',
                        'font-size': '12px',
                        'text-valign': 'center',
                        'text-halign': 'center',
                        'color': '#fff',
                        'text-outline-color': '#000',
                        'text-outline-width': '2px',
                        'width': 'data(size)',
                        'height': 'data(size)',
                        'border-width': 2,
                        'border-color': '#666'
                    }
                },
                {
                    selector: 'node.critical',
                    style: {
                        'background-color': '#ef4444',
                        'border-color': '#dc2626'
                    }
                },
                {
                    selector: 'node.important',
                    style: {
                        'background-color': '#f59e0b',
                        'border-color': '#d97706'
                    }
                },
                {
                    selector: 'node.normal',
                    style: {
                        'background-color': '#3b82f6',
                        'border-color': '#2563eb'
                    }
                },
                {
                    selector: 'node:selected',
                    style: {
                        'border-width': 4,
                        'border-color': '#10b981'
                    }
                },
                {
                    selector: 'edge',
                    style: {
                        'width': 2,
                        'line-color': '#999',
                        'target-arrow-color': '#999',
                        'target-arrow-shape': 'triangle',
                        'curve-style': 'bezier'
                    }
                },
                {
                    selector: 'edge.critical',
                    style: {
                        'width': 4,
                        'line-color': '#ef4444',
                        'target-arrow-color': '#ef4444'
                    }
                },
                {
                    selector: 'edge:selected',
                    style: {
                        'width': 4,
                        'line-color': '#10b981',
                        'target-arrow-color': '#10b981'
                    }
                }
            ],
            layout: {
                name: 'cose',
                animate: true,
                animationDuration: 500,
                idealEdgeLength: 100,
                nodeOverlap: 20,
                refresh: 20,
                fit: true,
                padding: 30,
                randomize: false,
                componentSpacing: 100,
                nodeRepulsion: 400000,
                edgeElasticity: 100,
                nestingFactor: 5,
                gravity: 80,
                numIter: 1000,
                initialTemp: 200,
                coolingFactor: 0.95,
                minTemp: 1.0
            },
            minZoom: 0.1,
            maxZoom: 3,
            wheelSensitivity: 0.2
        });
        
        this.cy.on('tap', 'node', (evt) => this.onNodeTap(evt));
        this.cy.on('tap', 'edge', (evt) => this.onEdgeTap(evt));
        this.cy.on('mouseover', 'node', (evt) => this.onNodeHover(evt));
        this.cy.on('mouseout', 'node', (evt) => this.onNodeHoverOut(evt));
    }
    
    loadGraph(jobId) {
        this.currentJobId = jobId;
        
        fetch(`/api/graph/${jobId}`)
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    console.error('Error loading graph:', data.error);
                    return;
                }
                
                this.graphData = data;
                this.renderGraph(data);
            })
            .catch(error => console.error('Error fetching graph:', error));
    }
    
    renderGraph(data) {
        if (!this.cy) return;
        
        const filteredNodes = data.nodes.filter(node => this.applyNodeFilters(node));
        const filteredEdges = data.edges.filter(edge => this.applyEdgeFilters(edge));
        
        const nodeIds = new Set(filteredNodes.map(n => n.data.id));
        
        const validEdges = filteredEdges.filter(edge => 
            nodeIds.has(edge.data.source) && nodeIds.has(edge.data.target)
        );
        
        this.cy.elements().remove();
        this.cy.add({ nodes: filteredNodes, edges: validEdges });
        this.cy.layout({ name: 'cose' }).run();
    }
    
    applyNodeFilters(node) {
        const complexity = node.data.complexity || 0;
        
        if (complexity < this.filters.minComplexity || complexity > this.filters.maxComplexity) {
            return false;
        }
        
        if (this.filters.searchQuery) {
            const query = this.filters.searchQuery.toLowerCase();
            const label = (node.data.label || '').toLowerCase();
            if (!label.includes(query)) {
                return false;
            }
        }
        
        if (this.filters.showOnlyCritical && !node.data.critical) {
            return false;
        }
        
        return true;
    }
    
    applyEdgeFilters(edge) {
        if (this.filters.showOnlyCritical && !edge.data.critical) {
            return false;
        }
        return true;
    }
    
    onNodeTap(evt) {
        const node = evt.target;
        const nodeId = node.data('id');
        const nodeName = node.data('label');
        
        if (window.remoteCollaborationManager) {
            window.remoteCollaborationManager.broadcastCursor('node', nodeId);
        }
        
        $(document).trigger('nodeSelected', {
            nodeId: nodeId,
            nodeName: nodeName,
            nodeData: node.data()
        });
    }
    
    onEdgeTap(evt) {
        const edge = evt.target;
        const sourceId = edge.data('source');
        const targetId = edge.data('target');
        
        $(document).trigger('edgeSelected', {
            sourceId: sourceId,
            targetId: targetId,
            edgeData: edge.data()
        });
    }
    
    onNodeHover(evt) {
        const node = evt.target;
        const tooltip = document.getElementById('graph-tooltip');
        
        if (tooltip) {
            tooltip.innerHTML = `
                <div class="bg-gray-800 text-white p-2 rounded shadow-lg text-sm">
                    <div class="font-bold">${node.data('label')}</div>
                    <div>Complexity: ${node.data('complexity') || 'N/A'}</div>
                    <div>Address: ${node.data('address') || 'N/A'}</div>
                </div>
            `;
            tooltip.style.display = 'block';
            tooltip.style.left = evt.originalEvent.clientX + 10 + 'px';
            tooltip.style.top = evt.originalEvent.clientY + 10 + 'px';
        }
    }
    
    onNodeHoverOut(evt) {
        const tooltip = document.getElementById('graph-tooltip');
        if (tooltip) {
            tooltip.style.display = 'none';
        }
    }
    
    setFilter(filterType, value) {
        this.filters[filterType] = value;
        if (this.graphData) {
            this.renderGraph(this.graphData);
        }
    }
    
    applyLayout(layoutName) {
        const layouts = {
            'cose': { name: 'cose' },
            'circle': { name: 'circle' },
            'grid': { name: 'grid' },
            'breadthfirst': { name: 'breadthfirst', directed: true },
            'concentric': { name: 'concentric' }
        };
        
        if (layouts[layoutName] && this.cy) {
            this.cy.layout(layouts[layoutName]).run();
        }
    }
    
    fitToView() {
        if (this.cy) {
            this.cy.fit(undefined, 50);
        }
    }
    
    centerOnNode(nodeId) {
        if (this.cy) {
            const node = this.cy.getElementById(nodeId);
            if (node) {
                this.cy.animate({
                    center: { eles: node },
                    zoom: 1.5
                }, {
                    duration: 500
                });
            }
        }
    }
    
    highlightPath(sourceId, targetId) {
        if (!this.cy) return;
        
        const bfs = this.cy.elements().bfs({
            roots: `#${sourceId}`,
            goal: `#${targetId}`,
            directed: true
        });
        
        this.cy.elements().removeClass('highlighted');
        
        bfs.addClass('highlighted');
        
        this.cy.style()
        this.cy.style()
            .selector('.highlighted')
            .style({
                'background-color': '#10b981',
                'line-color': '#10b981',
                'target-arrow-color': '#10b981',
                'width': 4
            });
    }
    
    exportImage(format = 'png') {
        if (!this.cy) return null;
        
        return this.cy.png({
            full: true,
            scale: 2
        });
    }
    
    destroy() {
        if (this.cy) {
            this.cy.destroy();
            this.cy = null;
        }
    }
}

$(document).ready(() => {
    window.graphVisualization = new GraphVisualization('graph-container');
    
    $(document).on('jobSelected', (e, jobId) => {
        if (window.graphVisualization) {
            window.graphVisualization.loadGraph(jobId);
        }
    });
    
    $('#graph-filter-input').on('input', (e) => {
        if (window.graphVisualization) {
            window.graphVisualization.setFilter('searchQuery', e.target.value);
        }
    });
    
    $('#graph-layout-select').on('change', (e) => {
        if (window.graphVisualization) {
            window.graphVisualization.applyLayout(e.target.value);
        }
    });
    
    $('#graph-fit-btn').on('click', () => {
        if (window.graphVisualization) {
            window.graphVisualization.fitToView();
        }
    });
    
    $('#graph-export-btn').on('click', () => {
        if (window.graphVisualization) {
            const imageData = window.graphVisualization.exportImage();
            if (imageData) {
                const link = document.createElement('a');
                link.download = 'graph.png';
                link.href = imageData;
                link.click();
            }
        }
    });
});
