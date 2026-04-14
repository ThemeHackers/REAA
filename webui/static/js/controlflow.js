$(document).ready(function() {
    let currentJobId = null;
    let currentFunctionAddress = null;
    let controlFlowData = null;
    function initControlFlowGraph(jobId, functionAddress) {
        currentJobId = jobId;
        currentFunctionAddress = functionAddress;
        $.get(`/api/jobs/${jobId}/controlflow/${functionAddress}`, function(data) {
            controlFlowData = data;
            renderControlFlowGraph(data, functionAddress);
        }).fail(function(xhr) {
            console.error('Failed to load control flow graph:', xhr);
            $('#controlflow-container').html('<div class="text-center text-gray-500 py-8">Failed to load control flow graph data</div>');
        });
    }
    function renderControlFlowGraph(data, functionAddress) {
        const container = $('#controlflow-container');
        container.empty();

        if (!data || !data.blocks || data.blocks.length === 0) {
            container.html('<div class="text-center text-gray-500 py-8">No control flow graph data available</div>');
            return;
        }

        const blocks = data.blocks;
        const summaryHtml = `
            <div class="cf-summary mb-6 p-4 bg-gray-800 rounded-lg border border-gray-700">
                <div class="flex items-center justify-between mb-3">
                    <h4 class="text-sm font-semibold text-gray-300">Control Flow Summary</h4>
                    <div class="flex gap-2 items-center">
                        <select id="cf-function-selector" class="px-2 py-1 bg-gray-700 border border-gray-600 rounded text-gray-300 text-xs">
                            <option value="">Select Function...</option>
                        </select>
                        <button id="cf-load-function" class="px-2 py-1 bg-blue-600 hover:bg-blue-700 text-white rounded text-xs">Load</button>
                    </div>
                </div>
                <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <div class="text-center">
                        <div class="text-2xl font-bold text-green-400">${blocks.length}</div>
                        <div class="text-xs text-gray-400">Basic Blocks</div>
                    </div>
                    <div class="text-center">
                        <div class="text-2xl font-bold text-blue-400">${functionAddress}</div>
                        <div class="text-xs text-gray-400">Function Address</div>
                    </div>
                    <div class="text-center">
                        <div class="text-2xl font-bold text-purple-400">${data.instructions || 0}</div>
                        <div class="text-xs text-gray-400">Instructions</div>
                    </div>
                    <div class="text-center">
                        <div class="text-2xl font-bold text-yellow-400">${data.edges || 0}</div>
                        <div class="text-xs text-gray-400">Edges</div>
                    </div>
                </div>
            </div>
        `;
        const graphHtml = `
            <div class="cf-graph mb-6 p-4 bg-gray-800 rounded-lg border border-gray-700">
                <div class="flex items-center justify-between mb-3">
                    <h4 class="text-sm font-semibold text-gray-300">Control Flow Graph</h4>
                    <div class="flex gap-2">
                        <select id="cf-layout-algorithm" class="px-2 py-1 bg-gray-700 hover:bg-gray-600 text-gray-300 rounded text-xs">
                            <option value="force">Force Layout</option>
                            <option value="hierarchical">Hierarchical Layout</option>
                        </select>
                        <button id="cf-zoom-in" class="px-2 py-1 bg-gray-700 hover:bg-gray-600 text-gray-300 rounded text-xs">+</button>
                        <button id="cf-zoom-out" class="px-2 py-1 bg-gray-700 hover:bg-gray-600 text-gray-300 rounded text-xs">-</button>
                        <button id="cf-reset" class="px-2 py-1 bg-gray-700 hover:bg-gray-600 text-gray-300 rounded text-xs">Reset</button>
                        <button id="cf-export" class="px-2 py-1 bg-blue-600 hover:bg-blue-700 text-white rounded text-xs">Export</button>
                        <select id="cf-export-format" class="px-2 py-1 bg-gray-700 border border-gray-600 rounded text-gray-300 text-xs">
                            <option value="svg">SVG</option>
                            <option value="png">PNG</option>
                            <option value="dot">DOT</option>
                        </select>
                    </div>
                </div>
                <div id="cf-graph-container" class="relative h-96 bg-gray-900 rounded-lg overflow-hidden"></div>
            </div>
        `;
        const blocksHtml = `
            <div class="cf-blocks">
                <h4 class="text-sm font-semibold text-gray-300 mb-3">Basic Blocks Detail</h4>
                <div class="space-y-2 max-h-64 overflow-y-auto">
                    ${blocks.map((block, index) => {
                        const blockType = getBlockType(block);
                        const colorClass = getBlockColor(blockType);
                        
                        return `
                            <div class="cf-block p-3 bg-gray-800 rounded-lg border border-gray-700 hover:border-gray-600 transition cursor-pointer mb-2" 
                                 data-block-index="${index}"
                                 data-type="${blockType}">
                                <div class="flex items-center justify-between mb-1">
                                    <span class="text-sm font-mono text-gray-300">0x${block.address.toString(16).toUpperCase()}</span>
                                    <span class="px-2 py-1 ${colorClass} text-white rounded text-xs font-bold capitalize">${blockType}</span>
                                </div>
                                <div class="text-xs text-gray-400">Instructions: ${block.instructions?.length || 0}</div>
                            </div>
                        `;
                    }).join('')}
                </div>
            </div>
        `;

        const instructionViewHtml = `
            <div class="cf-instruction-view mt-6 p-4 bg-gray-800 rounded-lg border border-gray-700">
                <div class="flex items-center justify-between mb-3">
                    <h4 class="text-sm font-semibold text-gray-300">Instruction View</h4>
                    <div class="flex gap-2">
                        <button id="cf-copy-asm" class="px-2 py-1 bg-gray-700 hover:bg-gray-600 text-gray-300 rounded text-xs">Copy Assembly</button>
                        <button id="cf-toggle-asm" class="px-2 py-1 bg-gray-700 hover:bg-gray-600 text-gray-300 rounded text-xs">Toggle View</button>
                    </div>
                </div>
                <div id="cf-instruction-content" class="bg-gray-900 rounded p-3 font-mono text-xs max-h-64 overflow-y-auto">
                    <div class="text-gray-500 text-center py-4">Select a block to view instructions</div>
                </div>
            </div>
        `;

        const xrefHtml = `
            <div class="cf-xref-panel mt-6 p-4 bg-gray-800 rounded-lg border border-gray-700">
                <div class="flex items-center justify-between mb-3">
                    <h4 class="text-sm font-semibold text-gray-300">Cross-References</h4>
                    <button id="cf-refresh-xref" class="px-2 py-1 bg-gray-700 hover:bg-gray-600 text-gray-300 rounded text-xs">Refresh</button>
                </div>
                <div class="grid grid-cols-2 gap-4">
                    <div>
                        <h5 class="text-xs font-semibold text-gray-400 mb-2">Calls To This Function</h5>
                        <div id="cf-xref-calls-to" class="bg-gray-900 rounded p-2 max-h-32 overflow-y-auto text-xs">
                            <div class="text-gray-500 text-center py-2">Loading...</div>
                        </div>
                    </div>
                    <div>
                        <h5 class="text-xs font-semibold text-gray-400 mb-2">Calls From This Function</h5>
                        <div id="cf-xref-calls-from" class="bg-gray-900 rounded p-2 max-h-32 overflow-y-auto text-xs">
                            <div class="text-gray-500 text-center py-2">Loading...</div>
                        </div>
                    </div>
                </div>
                <div class="mt-3">
                    <h5 class="text-xs font-semibold text-gray-400 mb-2">Data References</h5>
                    <div id="cf-xref-data" class="bg-gray-900 rounded p-2 max-h-24 overflow-y-auto text-xs">
                        <div class="text-gray-500 text-center py-2">Loading...</div>
                    </div>
                </div>
            </div>
        `;

        const patternHtml = `
            <div class="cf-pattern-panel mt-6 p-4 bg-gray-800 rounded-lg border border-gray-700">
                <div class="flex items-center justify-between mb-3">
                    <h4 class="text-sm font-semibold text-gray-300">Pattern Detection</h4>
                    <button id="cf-detect-patterns" class="px-2 py-1 bg-blue-600 hover:bg-blue-700 text-white rounded text-xs">Detect Patterns</button>
                </div>
                <div id="pattern-results" class="space-y-2 max-h-48 overflow-y-auto">
                    <div class="text-gray-500 text-center py-2 text-xs">Click "Detect Patterns" to analyze control flow</div>
                </div>
            </div>
        `;

        const annotationHtml = `
            <div class="cf-annotation-panel mt-6 p-4 bg-gray-800 rounded-lg border border-gray-700">
                <div class="flex items-center justify-between mb-3">
                    <h4 class="text-sm font-semibold text-gray-300">Block Annotations</h4>
                    <button id="cf-add-annotation" class="px-2 py-1 bg-green-600 hover:bg-green-700 text-white rounded text-xs">Add Annotation</button>
                </div>
                <div id="block-annotations" class="space-y-2 max-h-48 overflow-y-auto">
                    <div class="text-gray-500 text-center py-2 text-xs">Select a block to add annotations</div>
                </div>
            </div>
        `;

        container.html(summaryHtml + graphHtml + blocksHtml + instructionViewHtml + xrefHtml + patternHtml + annotationHtml);
        setupControlFlowHandlers();
        renderD3Graph(blocks);
    }
    function setupControlFlowHandlers() {
        $('#cf-layout-algorithm').on('change', () => renderD3Graph(controlFlowData.blocks));
        $('#cf-zoom-in').on('click', () => adjustCFZoom(1.2));
        $('#cf-zoom-out').on('click', () => adjustCFZoom(0.8));
        $('#cf-reset').on('click', () => resetCFZoom());
        $('#cf-export').on('click', exportControlFlowGraph);
        $('#cf-load-function').on('click', loadSelectedFunction);
        $('#cf-copy-asm').on('click', copyAssembly);
        $('#cf-toggle-asm').on('click', toggleAssemblyView);
        $('#cf-refresh-xref').on('click', loadCrossReferences);
        $('#cf-detect-patterns').on('click', detectPatterns);
        $('#cf-add-annotation').on('click', addBlockAnnotation);
        $('.cf-block').on('click', function() {
            const blockIndex = $(this).data('block-index');
            showBlockDetails(controlFlowData.blocks[blockIndex]);
            renderInstructionView(controlFlowData.blocks[blockIndex]);
        });
        loadFunctionList();
        loadCrossReferences();
    }
    function renderD3Graph(blocks) {
        const container = $('#cf-graph-container');
        container.empty();

        if (blocks.length === 0) return;

        const width = container.width();
        const height = 384;
        const layoutAlgorithm = $('#cf-layout-algorithm').val() || 'force';
        svg = d3.select('#cf-graph-container')
            .append('svg')
            .attr('width', '100%')
            .attr('height', height)
            .attr('viewBox', [0, 0, width, height]);
        const nodes = blocks.map((block, index) => ({
            id: index,
            address: block.address,
            type: getBlockType(block),
            instructions: block.instructions?.length || 0
        }));
        const links = [];
        blocks.forEach((block, index) => {
            if (block.edges && Array.isArray(block.edges)) {
                block.edges.forEach(edge => {
                    const targetIndex = blocks.findIndex(b => b.address === edge.target);
                    if (targetIndex !== -1) {
                        links.push({
                            source: index,
                            target: targetIndex,
                            condition: edge.condition || ''
                        });
                    }
                });
            }
        });
        if (layoutAlgorithm === 'hierarchical') {
            applyHierarchicalLayout(nodes, links, width, height);
        }
        let simulation;
        if (layoutAlgorithm === 'force') {
            simulation = d3.forceSimulation(nodes)
                .force('link', d3.forceLink(links).id(d => d.id).distance(120))
                .force('charge', d3.forceManyBody().strength(-300))
                .force('center', d3.forceCenter(width / 2, height / 2))
                .force('collide', d3.forceCollide().radius(50));
        }
        zoom = d3.zoom()
            .scaleExtent([0.5, 3])
            .on('zoom', (event) => {
                g.attr('transform', event.transform);
            });

        svg.call(zoom);

        const g = svg.append('g');
        const link = g.append('g')
            .selectAll('line')
            .data(links)
            .enter()
            .append('line')
            .attr('stroke', '#6366f1')
            .attr('stroke-width', 2)
            .attr('opacity', 0.7);
        const linkLabels = g.append('g')
            .selectAll('text')
            .data(links)
            .enter()
            .append('text')
            .text(d => d.condition)
            .attr('font-size', '10px')
            .attr('fill', '#9ca3af')
            .attr('text-anchor', 'middle');
        const node = g.append('g')
            .selectAll('g')
            .data(nodes)
            .enter()
            .append('g')
            .call(d3.drag()
                .on('start', dragstarted)
                .on('drag', dragged)
                .on('end', dragended))
            .on('mouseover', showBlockTooltip)
            .on('mouseout', hideTooltip);
        node.append('rect')
            .attr('width', 60)
            .attr('height', 30)
            .attr('rx', 5)
            .attr('fill', d => getNodeColor(d.type))
            .attr('stroke', '#fff')
            .attr('stroke-width', 2);
        node.append('text')
            .text(d => d.address ? d.address.substring(0, 6) : 'N/A')
            .attr('x', 30)
            .attr('y', 18)
            .attr('text-anchor', 'middle')
            .attr('fill', '#fff')
            .attr('font-size', '10px')
            .attr('font-family', 'monospace');
        if (simulation) {
            simulation.on('tick', () => {
                link
                    .attr('x1', d => d.source.x)
                    .attr('y1', d => d.source.y)
                    .attr('x2', d => d.target.x)
                    .attr('y2', d => d.target.y);

                linkLabels
                    .attr('x', d => (d.source.x + d.target.x) / 2)
                    .attr('y', d => (d.source.y + d.target.y) / 2);

                node.attr('transform', d => `translate(${d.x - 30},${d.y - 15})`);
            });
        } else {
            link
                .attr('x1', d => d.source.x)
                .attr('y1', d => d.source.y)
                .attr('x2', d => d.target.x)
                .attr('y2', d => d.target.y);

            linkLabels
                .attr('x', d => (d.source.x + d.target.x) / 2)
                .attr('y', d => (d.source.y + d.target.y) / 2);

            node.attr('transform', d => `translate(${d.x - 30},${d.y - 15})`);
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

        function showBlockTooltip(event, d) {
            const block = blocks[d.id];
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
                    <div style="font-weight: bold; margin-bottom: 5px;">${block.address}</div>
                    <div>Type: ${d.type}</div>
                    <div>Instructions: ${d.instructions}</div>
                `);

            tooltip.style('left', (event.pageX + 10) + 'px')
                   .style('top', (event.pageY - 10) + 'px');
        }

        function hideTooltip() {
            d3.selectAll('.tooltip').remove();
        }
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
        const levelHeight = height / (Object.keys(nodesByLevel).length || 1);
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
    function exportControlFlowGraph() {
        const format = $('#cf-export-format').val() || 'svg';
        
        if (format === 'svg') {
            const svgElement = document.querySelector('#cf-graph-container svg');
            if (!svgElement) return;

            const serializer = new XMLSerializer();
            const svgString = serializer.serializeToString(svgElement);
            const blob = new Blob([svgString], {type: 'image/svg+xml'});
            const url = URL.createObjectURL(blob);
            
            const link = document.createElement('a');
            link.href = url;
            link.download = `controlflow-${currentFunctionAddress || 'unknown'}.svg`;
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            URL.revokeObjectURL(url);
        } else if (format === 'png') {
            const svgElement = document.querySelector('#cf-graph-container svg');
            if (!svgElement) return;

            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            const svgData = new XMLSerializer().serializeToString(svgElement);
            const img = new Image();
            
            img.onload = function() {
                canvas.width = img.width;
                canvas.height = img.height;
                ctx.drawImage(img, 0, 0);
                
                const link = document.createElement('a');
                link.download = `controlflow-${currentFunctionAddress || 'unknown'}.png`;
                link.href = canvas.toDataURL('image/png');
                link.click();
            };
            
            img.src = 'data:image/svg+xml;base64,' + btoa(svgData);
        } else if (format === 'dot') {
            let dotContent = 'digraph controlflow {\n';
            dotContent += '  rankdir=TB;\n';
            dotContent += '  node [shape=rect, style=rounded];\n';
            
            controlFlowData.blocks.forEach((block, index) => {
                const label = `0x${block.address.toString(16).toUpperCase()}`;
                dotContent += `  block${index} [label="${label}"];\n`;
            });
            
            controlFlowData.blocks.forEach((block, index) => {
                if (block.edges) {
                    block.edges.forEach(edge => {
                        const targetIndex = controlFlowData.blocks.findIndex(b => b.address === edge.target);
                        if (targetIndex !== -1) {
                            const label = edge.condition || '';
                            dotContent += `  block${index} -> block${targetIndex} [label="${label}"];\n`;
                        }
                    });
                }
            });
            
            dotContent += '}';
            
            const blob = new Blob([dotContent], {type: 'text/plain'});
            const url = URL.createObjectURL(blob);
            
            const link = document.createElement('a');
            link.href = url;
            link.download = `controlflow-${currentFunctionAddress || 'unknown'}.dot`;
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            URL.revokeObjectURL(url);
        }
    }
    function loadFunctionList() {
        const selector = $('#cf-function-select');
        if (!selector.length) return;
        
        selector.empty();
        selector.append('<option value="">Select Function...</option>');
        
        $.get(`/api/jobs/${currentJobId}/functions`, function(data) {
            if (data.functions) {
                data.functions.forEach(func => {
                    selector.append(`<option value="${func.address}">${func.name || '0x' + func.address.toString(16)}</option>`);
                });
            }
        }).fail(function() {
            selector.append('<option value="">No functions available</option>');
        });
    }
    function loadSelectedFunction() {
        const address = $('#cf-function-select').val();
        if (address) {
            initControlFlowGraph(currentJobId, address);
        }
    }
    let currentBlock = null;
    let assemblyViewExpanded = false;
    function renderInstructionView(block) {
        currentBlock = block;
        const content = $('#cf-instruction-content');
        
        if (!block.instructions || block.instructions.length === 0) {
            content.html('<div class="text-gray-500 text-center py-4">No instructions available</div>');
            return;
        }
        
        let html = '';
        block.instructions.forEach((inst, index) => {
            const highlighted = highlightInstruction(inst);
            html += `<div class="hover:bg-gray-800 p-1 cursor-pointer" data-inst-index="${index}">
                <span class="text-blue-400">${index.toString().padStart(4, '0')}:</span> ${highlighted}
            </div>`;
        });
        
        content.html(html);
    }
    function highlightInstruction(instruction) {
        const parts = instruction.trim().split(/\s+/);
        if (parts.length === 0) return instruction;
        
        const mnemonic = parts[0].toLowerCase();
        const operands = parts.slice(1).join(' ');
        
        const colors = {
            'mov': '#10b981', 'movl': '#10b981', 'movq': '#10b981',
            'add': '#3b82f6', 'sub': '#3b82f6', 'mul': '#3b82f6', 'div': '#3b82f6',
            'jmp': '#f59e0b', 'call': '#f59e0b', 'ret': '#f59e0b',
            'je': '#ef4444', 'jne': '#ef4444', 'jg': '#ef4444', 'jl': '#ef4444', 'jge': '#ef4444', 'jle': '#ef4444',
            'cmp': '#8b5cf6', 'test': '#8b5cf6',
            'push': '#ec4899', 'pop': '#ec4899',
            'lea': '#06b6d4', 'nop': '#6b7280'
        };
        
        const color = colors[mnemonic] || '#e5e7eb';
        
        let highlightedOperands = operands;
        highlightedOperands = highlightedOperands.replace(/0x[0-9a-fA-F]+/g, '<span class="text-yellow-400">$&</span>');
        highlightedOperands = highlightedOperands.replace(/\b[rR][a-z0-9]+/g, '<span class="text-cyan-400">$&</span>');
        highlightedOperands = highlightedOperands.replace(/\b[eE][a-z][a-z0-9]+/g, '<span class="text-pink-400">$&</span>');
        
        return `<span style="color: ${color}">${mnemonic}</span> ${highlightedOperands}`;
    }
    function copyAssembly() {
        if (!currentBlock || !currentBlock.instructions) return;
        
        const asmText = currentBlock.instructions.join('\n');
        navigator.clipboard.writeText(asmText).then(() => {
            showToast('Assembly copied to clipboard', 'success');
        }).catch(() => {
            showToast('Failed to copy assembly', 'error');
        });
    }
    function toggleAssemblyView() {
        const content = $('#cf-instruction-content');
        assemblyViewExpanded = !assemblyViewExpanded;
        
        if (assemblyViewExpanded) {
            content.removeClass('max-h-64');
            content.addClass('max-h-96');
        } else {
            content.removeClass('max-h-96');
            content.addClass('max-h-64');
        }
    }
    function loadCrossReferences() {
        if (!currentFunctionAddress) return;
        
        $.get(`/api/jobs/${currentJobId}/xref/${currentFunctionAddress}`, function(data) {
            const callsTo = data.calls_to || [];
            const callsFrom = data.calls_from || [];
            const dataRefs = data.data_refs || [];
            
            $('#cf-xref-calls-to').html(
                callsTo.length > 0 
                    ? callsTo.map(xref => `
                        <div class="flex items-center justify-between p-1 hover:bg-gray-800 cursor-pointer" onclick="navigateToFunction('${xref.address}')">
                            <span class="text-blue-400 font-mono">0x${xref.address}</span>
                            <span class="text-gray-400">${xref.name || 'Unknown'}</span>
                        </div>
                    `).join('')
                    : '<div class="text-gray-500 text-center py-2">No calls to this function</div>'
            );
            
            $('#cf-xref-calls-from').html(
                callsFrom.length > 0 
                    ? callsFrom.map(xref => `
                        <div class="flex items-center justify-between p-1 hover:bg-gray-800 cursor-pointer" onclick="navigateToFunction('${xref.address}')">
                            <span class="text-green-400 font-mono">0x${xref.address}</span>
                            <span class="text-gray-400">${xref.name || 'Unknown'}</span>
                        </div>
                    `).join('')
                    : '<div class="text-gray-500 text-center py-2">No calls from this function</div>'
            );
            
            $('#cf-xref-data').html(
                dataRefs.length > 0 
                    ? dataRefs.map(xref => `
                        <div class="flex items-center justify-between p-1 hover:bg-gray-800">
                            <span class="text-yellow-400 font-mono">0x${xref.address}</span>
                            <span class="text-gray-400">${xref.type || 'Unknown'}</span>
                        </div>
                    `).join('')
                    : '<div class="text-gray-500 text-center py-2">No data references</div>'
            );
        }).fail(function() {
            $('#cf-xref-calls-to').html('<div class="text-red-400 text-center py-2">Failed to load cross-references</div>');
            $('#cf-xref-calls-from').html('<div class="text-red-400 text-center py-2">Failed to load cross-references</div>');
            $('#cf-xref-data').html('<div class="text-red-400 text-center py-2">Failed to load cross-references</div>');
        });
    }
    window.navigateToFunction = function(address) {
        initControlFlowGraph(currentJobId, address);
    };
    function detectPatterns() {
        if (!controlFlowData || !controlFlowData.blocks) {
            showToast('No control flow data available', 'warning');
            return;
        }
        
        const blocks = controlFlowData.blocks;
        const patterns = [];
        
        blocks.forEach(block => {
            const instructions = block.instructions || [];
            
            if (instructions.length > 0) {
                const lastInst = instructions[instructions.length - 1];
                
                if (lastInst.mnemonic === 'jmp' && lastInst.op_str) {
                    patterns.push({
                        type: 'Loop',
                        location: block.address,
                        description: 'Potential loop detected (unconditional jump)',
                        severity: 'info'
                    });
                }
                
                if (lastInst.mnemonic === 'jne' || lastInst.mnemonic === 'je') {
                    patterns.push({
                        type: 'Conditional Branch',
                        location: block.address,
                        description: 'Conditional branch detected',
                        severity: 'info'
                    });
                }
            }
            
            if (block.successors && block.successors.length > 2) {
                patterns.push({
                    type: 'Switch Case',
                    location: block.address,
                    description: `Switch-like structure detected (${block.successors.length} successors)`,
                    severity: 'warning'
                });
            }
            
            if (block.predecessors && block.predecessors.length > 3) {
                patterns.push({
                    type: 'Merge Point',
                    location: block.address,
                    description: `Merge point detected (${block.predecessors.length} predecessors)`,
                    severity: 'info'
                });
            }
        });
        
        renderPatternResults(patterns);
        showToast(`Detected ${patterns.length} patterns`, patterns.length > 0 ? 'success' : 'info');
    }
    function renderPatternResults(patterns) {
        const container = $('#pattern-results');
        
        if (patterns.length === 0) {
            container.html('<div class="text-gray-500 text-center py-2 text-xs">No patterns detected</div>');
            return;
        }
        
        container.html(patterns.map(pattern => `
            <div class="flex items-center justify-between p-2 bg-gray-900 rounded border-l-4 ${pattern.severity === 'warning' ? 'border-yellow-500' : 'border-blue-500'}">
                <div class="flex-1">
                    <div class="text-xs font-medium text-gray-300">${pattern.type}</div>
                    <div class="text-xs text-gray-400">0x${pattern.address.toString(16)} - ${pattern.description}</div>
                </div>
            </div>
        `).join(''));
    }
    let blockAnnotations = [];
    let selectedBlock = null;
    function addBlockAnnotation() {
        if (!selectedBlock) {
            showToast('Please select a block first', 'warning');
            return;
        }
        
        const note = prompt('Enter annotation note:');
        if (!note) return;
        
        const annotation = {
            id: 'annotation_' + Date.now(),
            blockAddress: selectedBlock.address,
            note: note,
            timestamp: Date.now()
        };
        
        blockAnnotations.push(annotation);
        localStorage.setItem(`cf_annotations_${currentJobId}`, JSON.stringify(blockAnnotations));
        renderBlockAnnotations();
        showToast('Annotation added successfully', 'success');
    }
    function renderBlockAnnotations() {
        const container = $('#block-annotations');
        
        if (blockAnnotations.length === 0) {
            container.html('<div class="text-gray-500 text-center py-2 text-xs">No annotations</div>');
            return;
        }
        
        container.html(blockAnnotations.map(ann => `
            <div class="flex items-center justify-between p-2 bg-gray-900 rounded">
                <div class="flex-1">
                    <div class="text-xs font-medium text-gray-300">0x${ann.blockAddress.toString(16)}</div>
                    <div class="text-xs text-gray-400">${ann.note}</div>
                </div>
                <button class="text-red-400 hover:text-red-300 text-xs" onclick="deleteBlockAnnotation('${ann.id}')">✕</button>
            </div>
        `).join(''));
    }
    window.deleteBlockAnnotation = function(id) {
        blockAnnotations = blockAnnotations.filter(a => a.id !== id);
        localStorage.setItem(`cf_annotations_${currentJobId}`, JSON.stringify(blockAnnotations));
        renderBlockAnnotations();
    };
    function showBlockDetails(block) {
        selectedBlock = block;
        $('#block-annotations').html('<div class="text-gray-500 text-center py-2 text-xs">Block selected - click "Add Annotation" to add notes</div>');
        renderBlockAnnotations();
    }
    let cfZoomScale = 1;

    function adjustCFZoom(factor) {
        cfZoomScale *= factor;
        cfZoomScale = Math.max(0.5, Math.min(3, cfZoomScale));
    }

    function resetCFZoom() {
        cfZoomScale = 1;
    }
    function getBlockType(block) {
        if (block.type) return block.type;
        if (block.is_entry) return 'entry';
        if (block.is_exit) return 'exit';
        if (block.is_conditional) return 'conditional';
        return 'normal';
    }
    function getBlockColor(type) {
        const colors = {
            'entry': '#10b981',
            'exit': '#ef4444',
            'conditional': '#f59e0b',
            'normal': '#6366f1',
            'default': '#8b5cf6'
        };
        return colors[type] || colors.default;
    }
    function getNodeColor(type) {
        const colors = {
            'entry': '#10b981',
            'exit': '#ef4444',
            'conditional': '#f59e0b',
            'normal': '#6366f1',
            'default': '#8b5cf6'
        };
        return colors[type] || colors.default;
    }
    function showBlockDetails(block) {
        const detailsHtml = `
            <div class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50" id="block-details-modal">
                <div class="bg-gray-800 rounded-lg p-6 max-w-lg w-full mx-4 border border-gray-700 max-h-[80vh] overflow-y-auto">
                    <div class="flex justify-between items-center mb-4">
                        <h3 class="text-lg font-semibold text-gray-300">Block Details</h3>
                        <button class="text-gray-400 hover:text-white" onclick="$('#block-details-modal').remove()">✕</button>
                    </div>
                    <div class="space-y-3">
                        <div>
                            <div class="text-sm text-gray-500">Address</div>
                            <div class="font-mono text-gray-300">0x${block.address.toString(16).toUpperCase()}</div>
                        </div>
                        <div>
                            <div class="text-sm text-gray-500">Type</div>
                            <div class="text-gray-300 capitalize">${getBlockType(block)}</div>
                        </div>
                        ${block.instructions ? `
                            <div>
                                <div class="text-sm text-gray-500 mb-2">Instructions</div>
                                <div class="bg-gray-900 rounded p-3 font-mono text-xs text-gray-300 space-y-1">
                                    ${block.instructions.map(inst => `<div>${inst}</div>`).join('')}
                                </div>
                            </div>
                        ` : ''}
                        ${block.edges ? `
                            <div>
                                <div class="text-sm text-gray-500 mb-2">Edges</div>
                                <div class="space-y-1">
                                    ${block.edges.map(edge => `
                                        <div class="text-xs text-gray-300">
                                            → 0x${edge.target.toString(16).toUpperCase()} ${edge.condition ? `(${edge.condition})` : ''}
                                        </div>
                                    `).join('')}
                                </div>
                            </div>
                        ` : ''}
                    </div>
                </div>
            </div>
        `;

        $('body').append(detailsHtml);
    }
    window.controlFlowManager = {
        initControlFlowGraph: initControlFlowGraph,
        renderControlFlowGraph: renderControlFlowGraph
    };
});
