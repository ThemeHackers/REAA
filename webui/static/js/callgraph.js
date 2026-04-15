$(document).ready(function() {
    
    if (typeof d3 === 'undefined') {
        console.error('D3.js is not loaded. Call graph visualization will not work.');
        $('#callgraph-container').html('<div class="text-center text-red-500 py-8">D3.js library is required but not loaded</div>');
        return;
    }

    let currentJobId = null;
    let graphData = null;
    let svg = null;
    let zoom = null;
    let originalNodes = [];
    let originalLinks = [];
    let selectedNodes = [];
    let nodeHistory = [];
    let historyIndex = -1;
    let lazyLoadThreshold = 500;
    let visibleNodes = [];
    let viewportObserver = null;
    function initCallGraph(jobId) {
        currentJobId = jobId;
        $.get(`/api/jobs/${jobId}/callgraph`, function(data) {
            graphData = data;
            renderCallGraph(data);
        }).fail(function(xhr) {
            console.error('Failed to load call graph:', xhr);
            $('#callgraph-container').html('<div class="text-center text-gray-500 py-8">Failed to load call graph data</div>');
        });
    }
    function renderCallGraph(data) {
        const container = $('#callgraph-container');
        container.empty();

        if (!data || !data.nodes || data.nodes.length === 0) {
            container.html('<div class="text-center text-gray-500 py-8">No call graph data available</div>');
            return;
        }
        const allNodes = data.nodes.map(n => ({
            id: n.id,
            name: n.name,
            type: n.type,
            connections: n.connections || 0,
            size: Math.max(5, Math.min(20, Math.sqrt(n.connections || 1) * 3)),
            x: n.x || Math.random() * 800,
            y: n.y || Math.random() * 500
        }));
        const allLinks = (data.links || []).map(l => ({
            source: l.source,
            target: l.target,
            connections: l.connections || 1
        }));
        
        originalNodes = allNodes;
        originalLinks = allLinks;
        
        let nodes, links;
        if (allNodes.length > lazyLoadThreshold) {
            nodes = allNodes.slice(0, lazyLoadThreshold);
            links = allLinks.filter(l => nodes.some(n => n.id === l.source) && nodes.some(n => n.id === l.target));
            visibleNodes = nodes;
            setupLazyLoading();
            $('#fg-total-nodes').text(nodes.length);
            $('#fg-total-edges').text(links.length);
            $('#fg-selected').text(0);
        } else {
            nodes = allNodes;
            links = allLinks;
            visibleNodes = nodes;
            $('#fg-total-nodes').text(nodes.length);
            $('#fg-total-edges').text(links.length);
            $('#fg-selected').text(0);
        }
        const nodeDegree = {};
        links.forEach(link => {
            nodeDegree[link.source] = (nodeDegree[link.source] || 0) + 1;
            nodeDegree[link.target] = (nodeDegree[link.target] || 0) + 1;
        });

        nodes.forEach(node => {
            node.connections = nodeDegree[node.id] || 0;
            node.size = Math.max(8, Math.min(25, 8 + node.connections * 2));
        });

        const minimapHtml = `
            <div id="graph-minimap" class="fixed bottom-4 right-4 w-48 h-36 bg-gray-800 border border-gray-700 rounded-lg z-30 overflow-hidden">
                <div class="absolute top-1 left-2 text-xs text-gray-400">Mini-map</div>
                <svg id="minimap-svg" class="w-full h-full"></svg>
                <div id="minimap-viewport" class="absolute border-2 border-blue-500 bg-blue-500/10 pointer-events-none"></div>
            </div>
        `;

        container.append(minimapHtml);
        const width = container.width() || 800;
        const height = 500;
        nodes.forEach(node => {
            node.x = width / 2 + (Math.random() - 0.5) * 50;
            node.y = height / 2 + (Math.random() - 0.5) * 50;
        });
        svg = d3.select('#callgraph-container')
            .append('svg')
            .attr('width', '100%')
            .attr('height', height)
            .attr('viewBox', [0, 0, width, height]);
        zoom = d3.zoom()
            .scaleExtent([0.1, 4])
            .on('zoom', (event) => {
                g.attr('transform', event.transform);
            });

        svg.call(zoom);
        const g = svg.append('g');
        const simulation = d3.forceSimulation(nodes)
            .force('link', d3.forceLink(links).id(d => d.id).distance(100))
            .force('charge', d3.forceManyBody().strength(-400))
            .force('center', d3.forceCenter(width / 2, height / 2))
            .force('collide', d3.forceCollide().radius(d => d.size + 5))
            .force('x', d3.forceX(width / 2).strength(0.05))
            .force('y', d3.forceY(height / 2).strength(0.05));
        const link = g.append('g')
            .selectAll('line')
            .data(links)
            .enter()
            .append('line')
            .attr('stroke', '#6366f1')
            .attr('stroke-width', d => Math.max(1, Math.min(3, d.connections / 5)))
            .attr('opacity', 0.7);
        const node = g.append('g')
            .selectAll('g')
            .data(nodes)
            .enter()
            .append('g')
            .call(d3.drag()
                .on('start', dragstarted)
                .on('drag', dragged)
                .on('end', dragended))
            .on('mouseover', showTooltip)
            .on('mouseout', hideTooltip)
            .on('click', handleNodeClick);
        node.append('circle')
            .attr('r', d => d.size)
            .attr('fill', d => getNodeColor(d))
            .attr('stroke', '#fff')
            .attr('stroke-width', 2)
            .style('cursor', 'pointer')
            .style('filter', 'drop-shadow(0px 2px 4px rgba(0,0,0,0.3))');
        node.append('text')
            .text(d => {
                const name = d.name || d.id || 'Unknown';
                return name.length > 15 ? name.substring(0, 12) + '...' : name;
            })
            .attr('x', d => d.size + 5)
            .attr('y', 4)
            .attr('fill', '#e5e7eb')
            .attr('font-size', '11px')
            .attr('font-family', 'monospace')
            .style('pointer-events', 'none');
        node.append('text')
            .text(d => d.connections)
            .attr('x', 0)
            .attr('y', 4)
            .attr('text-anchor', 'middle')
            .attr('fill', '#fff')
            .attr('font-size', '10px')
            .attr('font-weight', 'bold')
            .style('pointer-events', 'none');
        simulation.on('tick', () => {
            link
                .attr('x1', d => d.source.x)
                .attr('y1', d => d.source.y)
                .attr('x2', d => d.target.x)
                .attr('y2', d => d.target.y);

            node.attr('transform', d => `translate(${d.x},${d.y})`);
        });
        addLegend(container, height);
        setupFilterHandlers();
        setupKeyboardShortcuts();
        updateGraphStats();
        loadGraphFromCache();
        renderMinimap(nodes, links);
        setupMinimapHandlers();
        function dragstarted(event, d) {
            if (simulation && !event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
        }

        function dragged(event, d) {
            d.fx = event.x;
            d.fy = event.y;
        }

        function dragended(event, d) {
            if (simulation && !event.active) simulation.alphaTarget(0);
            d.fx = null;
            d.fy = null;
        }
        function showTooltip(event, d) {
            const tooltip = d3.select('body').append('div')
                .attr('class', 'tooltip')
                .style('position', 'absolute')
                .style('background', '#1f2937')
                .style('color', '#e5e7eb')
                .style('padding', '10px')
                .style('border-radius', '6px')
                .style('border', '1px solid #374151')
                .style('box-shadow', '0 4px 6px rgba(0,0,0,0.3)')
                .style('font-size', '12px')
                .style('z-index', '1000')
                .style('pointer-events', 'none')
                .html(`
                    <div style="font-weight: bold; margin-bottom: 5px;">${d.name || d.id || 'Unknown'}</div>
                    <div>Address: ${d.id}</div>
                    <div>Type: ${d.type || 'internal'}</div>
                    <div>Connections: ${d.connections}</div>
                    <div>Size: ${d.size} bytes</div>
                `);

            tooltip.style('left', (event.pageX + 10) + 'px')
                   .style('top', (event.pageY - 10) + 'px');
        }

        function hideTooltip() {
            d3.selectAll('.tooltip').remove();
        }
    }
    function getNodeColor(node) {
        const colors = {
            'entry': '#10b981',
            'export': '#3b82f6',
            'import': '#f59e0b',
            'internal': '#6366f1',
            'default': '#8b5cf6'
        };
        return colors[node.type] || colors.default;
    }
    function addLegend(container, height) {
        const legend = $('<div>')
            .css('position', 'absolute')
            .css('top', (height - 80) + 'px')
            .css('left', '10px')
            .css('background', 'rgba(31, 41, 55, 0.9)')
            .css('padding', '10px')
            .css('border-radius', '6px')
            .css('border', '1px solid #374151');

        const legendItems = [
            { type: 'entry', color: '#10b981', label: 'Entry Point' },
            { type: 'export', color: '#3b82f6', label: 'Export' },
            { type: 'import', color: '#f59e0b', label: 'Import' },
            { type: 'internal', color: '#6366f1', label: 'Internal' }
        ];

        legendItems.forEach(item => {
            const itemDiv = $('<div>')
                .css('display', 'flex')
                .css('align-items', 'center')
                .css('margin-bottom', '5px');

            itemDiv.append('div')
                .css('width', '12px')
                .css('height', '12px')
                .css('border-radius', '50%')
                .css('background', item.color)
                .css('margin-right', '8px');

            itemDiv.append('span')
                .css('color', '#e5e7eb')
                .css('font-size', '11px')
                .text(item.label);
        });

        container.append(legend);
    }
    function setupFilterHandlers() {
        $('#fg-search').on('input', applyFilters);
        $('#fg-layout').on('change', changeLayout);
        $('#fg-zoom-in').on('click', function() {
            if (zoom) zoom.scaleBy(1.3);
        });
        $('#fg-zoom-out').on('click', function() {
            if (zoom) zoom.scaleBy(0.7);
        });
        $('#fg-fit').on('click', function() {
            if (zoom) {
                const bounds = svg.node().getBBox();
                const width = bounds.width + 100;
                const height = bounds.height + 100;
                const scale = Math.min(container.width() / width, container.height() / height);
                zoom.transform(d3.zoomIdentity.translate(container.width() / 2 - bounds.x - bounds.width / 2, container.height() / 2 - bounds.y - bounds.height / 2).scale(scale));
            }
        });
        $('#fg-save').on('click', saveLayout);
        $('#fg-export').on('click', exportGraph);
    }
    function changeLayout() {
        const layoutAlgorithm = $('#fg-layout').val();
        applyFilters();
    }
    function applyLayout(nodes, links, width, height, algorithm) {
        switch (algorithm) {
            case 'circular':
                applyCircularLayout(nodes, width, height);
                break;
            case 'grid':
                applyGridLayout(nodes, width, height);
                break;
            case 'hierarchical':
                applyHierarchicalLayout(nodes, links, width, height);
                break;
            case 'force':
            default:
                break;
        }
    }
    function applyCircularLayout(nodes, width, height) {
        const centerX = width / 2;
        const centerY = height / 2;
        const radius = Math.min(width, height) / 2 - 50;
        const angleStep = (2 * Math.PI) / nodes.length;

        nodes.forEach((node, i) => {
            const angle = i * angleStep;
            node.x = centerX + radius * Math.cos(angle);
            node.y = centerY + radius * Math.sin(angle);
            node.fx = node.x;
            node.fy = node.y;
        });
    }
    function applyGridLayout(nodes, width, height) {
        const cols = Math.ceil(Math.sqrt(nodes.length));
        const rows = Math.ceil(nodes.length / cols);
        const cellWidth = width / cols;
        const cellHeight = height / rows;

        nodes.forEach((node, i) => {
            const col = i % cols;
            const row = Math.floor(i / cols);
            node.x = col * cellWidth + cellWidth / 2;
            node.y = row * cellHeight + cellHeight / 2;
            node.fx = node.x;
            node.fy = node.y;
        });
    }
    function applyHierarchicalLayout(nodes, links, width, height) {
        const adjacency = {};
        nodes.forEach(node => adjacency[node.id] = []);
        links.forEach(link => {
            if (adjacency[link.source]) {
                adjacency[link.source].push(link.target);
            }
        });

        const incomingCount = {};
        nodes.forEach(node => incomingCount[node.id] = 0);
        links.forEach(link => {
            incomingCount[link.target]++;
        });

        const entryNodes = nodes.filter(node => incomingCount[node.id] === 0);
        if (entryNodes.length === 0 && nodes.length > 0) {
            entryNodes.push(nodes[0]);
        }

        const levels = {};
        const queue = entryNodes.map(node => ({ node, level: 0 }));
        const visited = new Set();

        while (queue.length > 0) {
            const { node, level } = queue.shift();
            if (visited.has(node.id)) continue;
            visited.add(node.id);
            levels[node.id] = level;

            if (adjacency[node.id]) {
                adjacency[node.id].forEach(neighborId => {
                    const neighbor = nodes.find(n => n.id === neighborId);
                    if (neighbor && !visited.has(neighborId)) {
                        queue.push({ node: neighbor, level: level + 1 });
                    }
                });
            }
        }

        const nodesByLevel = {};
        Object.keys(levels).forEach(nodeId => {
            const level = levels[nodeId];
            if (!nodesByLevel[level]) nodesByLevel[level] = [];
            nodesByLevel[level].push(nodeId);
        });

        const numLevels = Object.keys(nodesByLevel).length || 1;
        const levelHeight = height / numLevels;
        Object.keys(nodesByLevel).forEach(level => {
            const levelNodes = nodesByLevel[level];
            const levelWidth = width / (levelNodes.length || 1);
            levelNodes.forEach((nodeId, i) => {
                const node = nodes.find(n => n.id === nodeId);
                if (node) {
                    node.x = i * levelWidth + levelWidth / 2;
                    node.y = parseInt(level) * levelHeight + levelHeight / 2;
                    node.fx = node.x;
                    node.fy = node.y;
                }
            });
        });
    }
    function applyFilters() {
        const searchTerm = $('#fg-search').val().toLowerCase();

        const filteredNodes = originalNodes.filter(node => {
            const matchesSearch = !searchTerm || 
                (node.name && node.name.toLowerCase().includes(searchTerm)) ||
                node.id.toLowerCase().includes(searchTerm);
            
            return matchesSearch;
        });

        const filteredNodeIds = new Set(filteredNodes.map(n => n.id));
        const filteredLinks = originalLinks.filter(link => 
            filteredNodeIds.has(link.source) && filteredNodeIds.has(link.target)
        );

        renderFilteredGraph(filteredNodes, filteredLinks);
        updateGraphStats(filteredNodes, filteredLinks);
    }
    function renderFilteredGraph(nodes, links) {
        const container = $('#callgraph-container');
        const width = container.width() || 800;
        const height = 500;
        const layoutAlgorithm = $('#fg-layout').val() || 'force';

        container.find('svg').remove();

        svg = d3.select('#callgraph-container')
            .append('svg')
            .attr('width', '100%')
            .attr('height', height)
            .attr('viewBox', [0, 0, width, height]);

        zoom = d3.zoom()
            .scaleExtent([0.1, 4])
            .on('zoom', (event) => {
                g.attr('transform', event.transform);
            });

        svg.call(zoom);

        const g = svg.append('g');

        applyLayout(nodes, links, width, height, layoutAlgorithm);

        let simulation;
        if (layoutAlgorithm === 'force') {
            simulation = d3.forceSimulation(nodes)
                .force('link', d3.forceLink(links).id(d => d.id).distance(100))
                .force('charge', d3.forceManyBody().strength(-400))
                .force('center', d3.forceCenter(width / 2, height / 2))
                .force('collide', d3.forceCollide().radius(d => d.size + 5))
                .force('x', d3.forceX(width / 2).strength(0.05))
                .force('y', d3.forceY(height / 2).strength(0.05));
        }

        const link = g.append('g')
            .selectAll('line')
            .data(links)
            .enter()
            .append('line')
            .attr('stroke', '#6366f1')
            .attr('stroke-width', d => Math.max(1, Math.min(3, d.connections / 5)))
            .attr('opacity', 0.7);

        const node = g.append('g')
            .selectAll('g')
            .data(nodes)
            .enter()
            .append('g')
            .call(d3.drag()
                .on('start', dragstarted)
                .on('drag', dragged)
                .on('end', dragended))
            .on('mouseover', showTooltip)
            .on('mouseout', hideTooltip);

        node.append('circle')
            .attr('r', d => d.size)
            .attr('fill', d => getNodeColor(d))
            .attr('stroke', '#fff')
            .attr('stroke-width', 2)
            .style('cursor', 'pointer')
            .style('filter', 'drop-shadow(0px 2px 4px rgba(0,0,0,0.3))');

        node.append('text')
            .text(d => {
                const name = d.name || d.id || 'Unknown';
                return name.length > 15 ? name.substring(0, 12) + '...' : name;
            })
            .attr('x', d => d.size + 5)
            .attr('y', 4)
            .attr('fill', '#e5e7eb')
            .attr('font-size', '11px')
            .attr('font-family', 'monospace')
            .style('pointer-events', 'none');

        node.append('text')
            .text(d => d.connections)
            .attr('x', 0)
            .attr('y', 4)
            .attr('text-anchor', 'middle')
            .attr('fill', '#fff')
            .attr('font-size', '10px')
            .attr('font-weight', 'bold')
            .style('pointer-events', 'none');

        if (simulation) {
            simulation.on('tick', () => {
                link
                    .attr('x1', d => d.source.x)
                    .attr('y1', d => d.source.y)
                    .attr('x2', d => d.target.x)
                    .attr('y2', d => d.target.y);

                node.attr('transform', d => `translate(${d.x},${d.y})`);
            });
        } else {
            link
                .attr('x1', d => d.source.x)
                .attr('y1', d => d.source.y)
                .attr('x2', d => d.target.x)
                .attr('y2', d => d.target.y);

            node.attr('transform', d => `translate(${d.x},${d.y})`);
        }

        function dragstarted(event, d) {
            if (simulation && !event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
        }

        function dragged(event, d) {
            d.fx = event.x;
            d.fy = event.y;
        }

        function dragended(event, d) {
            if (simulation && !event.active) simulation.alphaTarget(0);
            d.fx = null;
            d.fy = null;
        }

        function showTooltip(event, d) {
            const tooltip = d3.select('body').append('div')
                .attr('class', 'tooltip')
                .style('position', 'absolute')
                .style('background', '#1f2937')
                .style('color', '#e5e7eb')
                .style('padding', '10px')
                .style('border-radius', '6px')
                .style('border', '1px solid #374151')
                .style('box-shadow', '0 4px 6px rgba(0,0,0,0.3)')
                .style('font-size', '12px')
                .style('z-index', '1000')
                .style('pointer-events', 'none')
                .html(`
                    <div style="font-weight: bold; margin-bottom: 5px;">${d.name || d.id || 'Unknown'}</div>
                    <div>Address: ${d.id}</div>
                    <div>Type: ${d.type || 'internal'}</div>
                    <div>Connections: ${d.connections}</div>
                    <div>Size: ${d.size} bytes</div>
                `);

            tooltip.style('left', (event.pageX + 10) + 'px')
                   .style('top', (event.pageY - 10) + 'px');
        }

        function hideTooltip() {
            d3.selectAll('.tooltip').remove();
        }

        addLegend(container, height);
    }
    function resetFilters() {
        $('#fg-search').val('');
        renderCallGraph(graphData);
    }
    function updateGraphStats(nodes, links) {
        const displayNodes = nodes || originalNodes;
        const displayLinks = links || originalLinks;
        
        $('#fg-total-nodes').text(displayNodes.length);
        $('#fg-total-edges').text(displayLinks.length);
        $('#fg-selected').text(selectedNodes.length);
    }
    function exportGraph() {
        const svgElement = document.querySelector('#callgraph-container svg');
        if (!svgElement) return;

        const serializer = new XMLSerializer();
        const svgString = serializer.serializeToString(svgElement);
        const blob = new Blob([svgString], {type: 'image/svg+xml'});
        const url = URL.createObjectURL(blob);
        
        const link = document.createElement('a');
        link.href = url;
        link.download = `callgraph-${currentJobId}.svg`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
    }
    function handleNodeClick(event, d) {
        selectedNodes = [d];
        showNodeDetails(d);
        saveToHistory();
    }
    function showNodeDetails(node) {
        const content = $('#fg-node-details');
        
        if (!content.length) return;
        
        const callers = originalLinks.filter(l => l.target === node.id).map(l => {
            const caller = originalNodes.find(n => n.id === l.source);
            return caller ? caller.name || caller.id : l.source;
        });
        
        const callees = originalLinks.filter(l => l.source === node.id).map(l => {
            const callee = originalNodes.find(n => n.id === l.target);
            return callee ? callee.name || callee.id : l.target;
        });
        
        content.html(`
            <div class="space-y-3">
                <div>
                    <div class="text-sm text-gray-500">Name</div>
                    <div class="font-mono text-white text-sm">${node.name || node.id || 'Unknown'}</div>
                </div>
                <div>
                    <div class="text-sm text-gray-500">Address</div>
                    <div class="font-mono text-gray-300 text-sm">0x${node.id}</div>
                </div>
                <div>
                    <div class="text-sm text-gray-500">Type</div>
                    <div class="text-gray-300 capitalize">${node.type || 'internal'}</div>
                </div>
                <div>
                    <div class="text-sm text-gray-500">Connections</div>
                    <div class="text-gray-300">${node.connections}</div>
                </div>
                <div>
                    <div class="text-sm text-gray-500">Size</div>
                    <div class="text-gray-300">${node.size || 'N/A'}</div>
                </div>
            </div>
        `);
    }
    function setupNodePanelHandlers() {
        
    }
    function setupLayoutHandlers() {
    }
    function setupKeyboardShortcuts() {
        $(document).on('keydown', function(e) {
            if ($('#function-graph-modal').hasClass('hidden')) return;
            
            if (e.key === 'Escape') {
                selectedNodes = [];
                clearPathHighlight();
            } else if (e.key === '+' || e.key === '=') {
                if (zoom) {
                    svg.transition().duration(300).call(zoom.scaleBy, 1.2);
                }
            } else if (e.key === '-') {
                if (zoom) {
                    svg.transition().duration(300).call(zoom.scaleBy, 0.8);
                }
            } else if (e.key === 'z' && (e.ctrlKey || e.metaKey)) {
                e.preventDefault();
                if (e.shiftKey) {
                    redo();
                } else {
                    undo();
                }
            }
        });
    }
    function highlightPath(startNode) {
        const path = findPath(startNode);
        if (path.length === 0) return;
        
        d3.selectAll('line').attr('stroke', '#6366f1').attr('stroke-width', d => Math.max(1, Math.min(3, d.connections / 5))).attr('opacity', 0.3);
        d3.selectAll('circle').attr('opacity', 0.3);
        
        const pathNodeIds = new Set(path);
        const pathLinks = originalLinks.filter(l => pathNodeIds.has(l.source) && pathNodeIds.has(l.target));
        const pathLinkSet = new Set(pathLinks.map(l => `${l.source}-${l.target}`));
        
        d3.selectAll('line').filter(d => pathLinkSet.has(`${d.source.id}-${d.target.id}`))
            .attr('stroke', '#f59e0b')
            .attr('stroke-width', 4)
            .attr('opacity', 1);
        
        d3.selectAll('circle').filter(d => pathNodeIds.has(d.id))
            .attr('opacity', 1)
            .attr('stroke', '#f59e0b')
            .attr('stroke-width', 3);
    }
    function clearPathHighlight() {
        d3.selectAll('line').attr('stroke', '#6366f1').attr('stroke-width', d => Math.max(1, Math.min(3, d.connections / 5))).attr('opacity', 0.7);
        d3.selectAll('circle').attr('opacity', 1).attr('stroke', '#fff').attr('stroke-width', 2);
    }
    function findPath(startNode, visited = new Set()) {
        const path = [startNode.id];
        visited.add(startNode.id);
        
        const neighbors = originalLinks
            .filter(l => l.source === startNode.id)
            .map(l => l.target)
            .filter(id => !visited.has(id));
        
        if (neighbors.length === 0) return path;
        
        const nextNode = originalNodes.find(n => n.id === neighbors[0]);
        if (nextNode) {
            path.push(...findPath(nextNode, visited));
        }
        
        return path;
    }
    function saveToHistory() {
        if (historyIndex < nodeHistory.length - 1) {
            nodeHistory = nodeHistory.slice(0, historyIndex + 1);
        }
        nodeHistory.push(JSON.parse(JSON.stringify(selectedNodes)));
        historyIndex++;
    }
    function undo() {
        if (historyIndex > 0) {
            historyIndex--;
            selectedNodes = nodeHistory[historyIndex];
            if (selectedNodes.length > 0) {
                showNodeDetails(selectedNodes[0]);
            }
        }
    }
    function redo() {
        if (historyIndex < nodeHistory.length - 1) {
            historyIndex++;
            selectedNodes = nodeHistory[historyIndex];
            if (selectedNodes.length > 0) {
                showNodeDetails(selectedNodes[0]);
            }
        }
    }
    function saveLayout() {
        const layoutData = {
            jobId: currentJobId,
            nodes: originalNodes.map(n => ({ id: n.id, x: n.x, y: n.y, fx: n.fx, fy: n.fy, annotation: n.annotation }))
        };
        localStorage.setItem(`callgraph_layout_${currentJobId}`, JSON.stringify(layoutData));
        showToast('Layout saved successfully', 'success');
    }
    function loadLayout() {
        const saved = localStorage.getItem(`callgraph_layout_${currentJobId}`);
        if (saved) {
            const layoutData = JSON.parse(saved);
            originalNodes.forEach(node => {
                const savedNode = layoutData.nodes.find(n => n.id === node.id);
                if (savedNode) {
                    node.x = savedNode.x;
                    node.y = savedNode.y;
                    node.fx = savedNode.fx;
                    node.fy = savedNode.fy;
                    node.annotation = savedNode.annotation;
                }
            });
            renderCallGraph(graphData);
            showToast('Layout loaded successfully', 'success');
        } else {
            showToast('No saved layout found', 'warning');
        }
    }
    function saveGraphToCache() {
        const cacheData = {
            jobId: currentJobId,
            data: graphData,
            timestamp: Date.now()
        };
        localStorage.setItem(`callgraph_cache_${currentJobId}`, JSON.stringify(cacheData));
    }
    function loadGraphFromCache() {
        const cached = localStorage.getItem(`callgraph_cache_${currentJobId}`);
        if (cached) {
            const cacheData = JSON.parse(cached);
            if (cacheData.jobId === currentJobId) {
                graphData = cacheData.data;
            }
        }
    }
    function renderMinimap(nodes, links) {
        const minimapSvg = d3.select('#minimap-svg');
        minimapSvg.selectAll('*').remove();
        
        const width = 192;
        const height = 144;
        
        const xExtent = d3.extent(nodes, d => d.x);
        const yExtent = d3.extent(nodes, d => d.y);
        const xScale = d3.scaleLinear().domain(xExtent).range([10, width - 10]);
        const yScale = d3.scaleLinear().domain(yExtent).range([10, height - 10]);
        
        minimapSvg.attr('width', width).attr('height', height);
        
        minimapSvg.append('g')
            .selectAll('line')
            .data(links)
            .enter()
            .append('line')
            .attr('x1', d => xScale(d.source.x))
            .attr('y1', d => yScale(d.source.y))
            .attr('x2', d => xScale(d.target.x))
            .attr('y2', d => yScale(d.target.y))
            .attr('stroke', '#6366f1')
            .attr('stroke-width', 0.5)
            .attr('opacity', 0.5);
        
        minimapSvg.append('g')
            .selectAll('circle')
            .data(nodes)
            .enter()
            .append('circle')
            .attr('cx', d => xScale(d.x))
            .attr('cy', d => yScale(d.y))
            .attr('r', 2)
            .attr('fill', d => getNodeColor(d))
            .attr('opacity', 0.7);
        
        updateMinimapViewport();
    }
    function updateMinimapViewport() {
        if (!zoom) return;
        
        const mainSvg = d3.select('#callgraph-container svg');
        const transform = d3.zoomTransform(mainSvg.node());
        
        const minimapWidth = 192;
        const minimapHeight = 144;
        const mainWidth = $('#callgraph-container').width();
        const mainHeight = 500;
        
        const viewport = d3.select('#minimap-viewport');
        
        const scale = transform.k;
        const translateX = transform.x;
        const translateY = transform.y;
        
        const vpWidth = (mainWidth / scale) / mainWidth * minimapWidth;
        const vpHeight = (mainHeight / scale) / mainHeight * minimapHeight;
        const vpX = (-translateX / scale) / mainWidth * minimapWidth;
        const vpY = (-translateY / scale) / mainHeight * minimapHeight;
        
        viewport.style('left', vpX + 'px')
               .style('top', vpY + 'px')
               .style('width', vpWidth + 'px')
               .style('height', vpHeight + 'px');
    }
    function setupMinimapHandlers() {
        const minimapSvg = d3.select('#minimap-svg');
        const viewport = d3.select('#minimap-viewport');
        
        minimapSvg.on('click', function(event) {
            const rect = this.getBoundingClientRect();
            const x = event.clientX - rect.left;
            const y = event.clientY - rect.top;
            
            const minimapWidth = 192;
            const minimapHeight = 144;
            const mainWidth = $('#callgraph-container').width();
            const mainHeight = 500;
            
            const targetX = (x / minimapWidth) * mainWidth - mainWidth / 2;
            const targetY = (y / minimapHeight) * mainHeight - mainHeight / 2;
            
            if (zoom) {
                svg.transition().duration(300).call(zoom.translateTo, targetX, targetY);
            }
        });
        
        zoom.on('zoom', () => {
            updateMinimapViewport();
        });
    }
    function setupLazyLoading() {
        if (!zoom) return;
        
        zoom.on('zoom.lazy', function(event) {
            const transform = d3.zoomTransform(this);
            const scale = transform.k;
            
            if (scale > 1.5) {
                loadMoreNodes();
            }
        });
    }
    function loadMoreNodes() {
        if (visibleNodes.length >= originalNodes.length) return;
        
        const batchSize = 100;
        const startIndex = visibleNodes.length;
        const endIndex = Math.min(startIndex + batchSize, originalNodes.length);
        
        const newNodes = originalNodes.slice(startIndex, endIndex);
        visibleNodes.push(...newNodes);
        
        const newLinks = originalLinks.filter(l => 
            visibleNodes.some(n => n.id === l.source) && visibleNodes.some(n => n.id === l.target)
        );
        
        updateGraphWithNewNodes(newNodes, newLinks);
        
        $('#fg-total-nodes').text(visibleNodes.length);
        $('#fg-total-edges').text(originalLinks.filter(l => visibleNodes.some(n => n.id === l.source) && visibleNodes.some(n => n.id === l.target)).length);
    }
    function updateGraphWithNewNodes(newNodes, newLinks) {
        const g = svg.select('g');
        
        const node = g.append('g')
            .selectAll('g')
            .data(newNodes)
            .enter()
            .append('g')
            .call(d3.drag()
                .on('start', dragstarted)
                .on('drag', dragged)
                .on('end', dragended))
            .on('mouseover', showTooltip)
            .on('mouseout', hideTooltip)
            .on('click', handleNodeClick);
            
        node.append('circle')
            .attr('r', d => d.size)
            .attr('fill', d => getNodeColor(d))
            .attr('stroke', '#fff')
            .attr('stroke-width', 2)
            .style('cursor', 'pointer')
            .style('filter', 'drop-shadow(0px 2px 4px rgba(0,0,0,0.3))');
            
        node.append('text')
            .text(d => {
                const name = d.name || d.id || 'Unknown';
                return name.length > 15 ? name.substring(0, 12) + '...' : name;
            })
            .attr('x', d => d.size + 5)
            .attr('y', 4)
            .attr('fill', '#e5e7eb')
            .attr('font-size', '11px')
            .attr('font-family', 'monospace')
            .style('pointer-events', 'none');
            
        node.append('text')
            .text(d => d.connections)
            .attr('x', 0)
            .attr('y', 4)
            .attr('text-anchor', 'middle')
            .attr('fill', '#fff')
            .attr('font-size', '10px')
            .attr('font-weight', 'bold')
            .style('pointer-events', 'none');
    }
    let nodeGroups = [];
    function groupSelectedNodes() {
        if (selectedNodes.length < 2) {
            showToast('Select at least 2 nodes to group', 'warning');
            return;
        }
        
        const groupName = prompt('Enter group name:') || 'Group ' + (nodeGroups.length + 1);
        const groupId = 'group_' + Date.now();
        
        selectedNodes.forEach(node => {
            node.groupId = groupId;
            node.groupName = groupName;
            node.isGrouped = true;
        });
        
        nodeGroups.push({
            id: groupId,
            name: groupName,
            nodeIds: selectedNodes.map(n => n.id)
        });
        
        renderCallGraph(graphData);
        showToast(`Grouped ${selectedNodes.length} nodes as "${groupName}"`, 'success');
    }
    function ungroupAllNodes() {
        originalNodes.forEach(node => {
            delete node.groupId;
            delete node.groupName;
            node.isGrouped = false;
        });
        
        nodeGroups = [];
        renderCallGraph(graphData);
        showToast('All nodes ungrouped', 'success');
    }
    function clusterByType() {
        const types = {};
        originalNodes.forEach(node => {
            const type = node.type || 'internal';
            if (!types[type]) types[type] = [];
            types[type].push(node.id);
        });
        
        Object.keys(types).forEach(type => {
            if (types[type].length > 1) {
                const groupId = 'cluster_' + type;
                types[type].forEach(nodeId => {
                    const node = originalNodes.find(n => n.id === nodeId);
                    if (node) {
                        node.groupId = groupId;
                        node.groupName = type.charAt(0).toUpperCase() + type.slice(1) + ' Cluster';
                        node.isGrouped = true;
                    }
                });
                
                nodeGroups.push({
                    id: groupId,
                    name: type.charAt(0).toUpperCase() + type.slice(1) + ' Cluster',
                    nodeIds: types[type]
                });
            }
        });
        
        renderCallGraph(graphData);
        showToast(`Clustered nodes by type`, 'success');
    }
    window.callGraphManager = {
        initCallGraph: initCallGraph,
        renderCallGraph: renderCallGraph
    };
});
