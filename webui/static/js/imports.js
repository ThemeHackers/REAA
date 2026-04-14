$(document).ready(function() {
    let currentJobId = null;
    let importExportData = null;
    let svg = null;
    let zoom = null;
    function initImportExportGraph(jobId) {
        currentJobId = jobId;
        $.get(`/api/jobs/${jobId}/imports`, function(data) {
            importExportData = data;
            renderImportExportGraph(data);
        }).fail(function(xhr) {
            console.error('Failed to load import/export data:', xhr);
            $('#import-export-container').html('<div class="text-center text-gray-500 py-8">Failed to load import/export data</div>');
        });
    }
    function renderImportExportGraph(data) {
        const container = $('#import-export-container');
        container.empty();

        if (!data || (!data.imports && !data.exports)) {
            container.html('<div class="text-center text-gray-500 py-8">No import/export data available</div>');
            return;
        }

        const imports = data.imports || [];
        const exports = data.exports || [];
        const summaryHtml = `
            <div class="import-export-summary mb-6 p-4 bg-gray-800 rounded-lg border border-gray-700">
                <h4 class="text-sm font-semibold text-gray-300 mb-3">Import/Export Summary</h4>
                <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <div class="text-center">
                        <div class="text-2xl font-bold text-orange-400">${imports.length}</div>
                        <div class="text-xs text-gray-400">Imports</div>
                    </div>
                    <div class="text-center">
                        <div class="text-2xl font-bold text-green-400">${exports.length}</div>
                        <div class="text-xs text-gray-400">Exports</div>
                    </div>
                    <div class="text-center">
                        <div class="text-2xl font-bold text-blue-400">${data.libraries ? data.libraries.length : 0}</div>
                        <div class="text-xs text-gray-400">Libraries</div>
                    </div>
                    <div class="text-center">
                        <div class="text-2xl font-bold text-purple-400">${imports.length + exports.length}</div>
                        <div class="text-xs text-gray-400">Total Symbols</div>
                    </div>
                </div>
            </div>
        `;
        const controlsHtml = `
            <div class="import-export-controls mb-6 p-4 bg-gray-800 rounded-lg border border-gray-700">
                <div class="flex flex-wrap gap-4 items-center">
                    <div class="flex-1 min-w-[200px]">
                        <input type="text" id="import-export-search" placeholder="Search symbols..." 
                               class="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-gray-200 text-sm focus:outline-none focus:border-blue-500">
                    </div>
                    <div>
                        <select id="import-export-type-filter" class="px-3 py-2 bg-gray-700 border border-gray-600 rounded text-gray-200 text-sm focus:outline-none focus:border-blue-500">
                            <option value="">All Types</option>
                            <option value="import">Imports</option>
                            <option value="export">Exports</option>
                        </select>
                    </div>
                    <div>
                        <select id="import-export-library-filter" class="px-3 py-2 bg-gray-700 border border-gray-600 rounded text-gray-200 text-sm focus:outline-none focus:border-blue-500">
                            <option value="">All Libraries</option>
                            ${data.libraries ? data.libraries.map(lib => `<option value="${lib}">${lib}</option>`).join('') : ''}
                        </select>
                    </div>
                    <div class="flex gap-2">
                        <button id="import-export-reset" class="px-3 py-2 bg-gray-700 hover:bg-gray-600 text-gray-200 rounded text-sm">Reset</button>
                        <button id="import-export-export" class="px-3 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded text-sm">Export</button>
                    </div>
                </div>
                <div id="import-export-stats" class="text-xs text-gray-400 mt-2"></div>
            </div>
        `;
        const graphHtml = `
            <div class="import-export-graph mb-6 p-4 bg-gray-800 rounded-lg border border-gray-700">
                <div class="flex items-center justify-between mb-3">
                    <h4 class="text-sm font-semibold text-gray-300">Dependency Graph</h4>
                    <div class="flex gap-2">
                        <button id="ie-zoom-in" class="px-2 py-1 bg-gray-700 hover:bg-gray-600 text-gray-300 rounded text-xs">+</button>
                        <button id="ie-zoom-out" class="px-2 py-1 bg-gray-700 hover:bg-gray-600 text-gray-300 rounded text-xs">-</button>
                        <button id="ie-reset" class="px-2 py-1 bg-gray-700 hover:bg-gray-600 text-gray-300 rounded text-xs">Reset</button>
                    </div>
                </div>
                <div id="ie-graph-container" class="relative h-96 bg-gray-900 rounded-lg overflow-hidden"></div>
            </div>
        `;
        const tablesHtml = `
            <div class="import-export-tables grid grid-cols-1 md:grid-cols-2 gap-4">
                <div class="imports-section">
                    <h4 class="text-sm font-semibold text-gray-300 mb-3">Imports (${imports.length})</h4>
                    <div class="max-h-64 overflow-y-auto" id="imports-table">
                        ${imports.map((imp, index) => `
                            <div class="import-item p-3 bg-gray-800 rounded-lg border border-gray-700 hover:border-gray-600 transition cursor-pointer mb-2" 
                                 data-type="import"
                                 data-index="${index}"
                                 data-library="${imp.library || ''}">
                                <div class="flex items-center justify-between mb-1">
                                    <span class="text-sm text-gray-300 font-mono">${escapeHtml(imp.name)}</span>
                                    <span class="px-2 py-1 bg-orange-600 text-white rounded text-xs">IMPORT</span>
                                </div>
                                <div class="text-xs text-gray-400">Library: ${escapeHtml(imp.library || 'Unknown')}</div>
                            </div>
                        `).join('')}
                    </div>
                </div>
                <div class="exports-section">
                    <h4 class="text-sm font-semibold text-gray-300 mb-3">Exports (${exports.length})</h4>
                    <div class="max-h-64 overflow-y-auto" id="exports-table">
                        ${exports.map((exp, index) => `
                            <div class="export-item p-3 bg-gray-800 rounded-lg border border-gray-700 hover:border-gray-600 transition cursor-pointer mb-2" 
                                 data-type="export"
                                 data-index="${index}"
                                 data-address="${exp.address || ''}">
                                <div class="flex items-center justify-between mb-1">
                                    <span class="text-sm text-gray-300 font-mono">${escapeHtml(exp.name)}</span>
                                    <span class="px-2 py-1 bg-green-600 text-white rounded text-xs">EXPORT</span>
                                </div>
                                <div class="text-xs text-gray-400">Address: ${exp.address ? '0x' + exp.address.toString(16).toUpperCase() : 'Unknown'}</div>
                            </div>
                        `).join('')}
                    </div>
                </div>
            </div>
        `;

        container.html(summaryHtml + controlsHtml + graphHtml + tablesHtml);
        setupImportExportHandlers(data);
        renderD3Graph(data);
    }
    function setupImportExportHandlers(data) {
        $('#import-export-search').on('input', filterImportExport);
        $('#import-export-type-filter').on('change', filterImportExport);
        $('#import-export-library-filter').on('change', filterImportExport);
        $('#import-export-reset').on('click', resetImportExportFilters);
        $('#import-export-export').on('click', exportImportExport);
        $('#ie-zoom-in').on('click', () => adjustIEZoom(1.2));
        $('#ie-zoom-out').on('click', () => adjustIEZoom(0.8));
        $('#ie-reset').on('click', () => resetIEZoom());
    }
    function renderD3Graph(data) {
        const container = $('#ie-graph-container');
        container.empty();

        if (!data) return;

        const imports = data.imports || [];
        const exports = data.exports || [];
        const libraries = data.libraries || [];

        const width = container.width();
        const height = 384;
        svg = d3.select('#ie-graph-container')
            .append('svg')
            .attr('width', '100%')
            .attr('height', height)
            .attr('viewBox', [0, 0, width, height]);
        const nodes = [
            { id: 'binary', name: 'Binary', type: 'binary', size: 30 },
            ...libraries.map((lib, i) => ({
                id: lib,
                name: lib,
                type: 'library',
                size: 20
            }))
        ];
        const links = [];
        const libraryImports = {};
        imports.forEach(imp => {
            const lib = imp.library || 'unknown';
            if (!libraryImports[lib]) libraryImports[lib] = 0;
            libraryImports[lib]++;
        });

        Object.keys(libraryImports).forEach(lib => {
            const libNode = nodes.find(n => n.id === lib);
            if (libNode) {
                links.push({
                    source: 'binary',
                    target: lib,
                    count: libraryImports[lib]
                });
            }
        });
        const simulation = d3.forceSimulation(nodes)
            .force('link', d3.forceLink(links).id(d => d.id).distance(150))
            .force('charge', d3.forceManyBody().strength(-300))
            .force('center', d3.forceCenter(width / 2, height / 2))
            .force('collide', d3.forceCollide().radius(40));
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
            .attr('stroke-width', d => Math.max(1, Math.min(5, d.count / 2)))
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
            .attr('fill', d => d.type === 'binary' ? '#10b981' : '#f59e0b')
            .attr('stroke', '#fff')
            .attr('stroke-width', 2);
        node.append('text')
            .text(d => d.name.length > 15 ? d.name.substring(0, 12) + '...' : d.name)
            .attr('x', d => d.size + 5)
            .attr('y', 4)
            .attr('fill', '#e5e7eb')
            .attr('font-size', '11px')
            .attr('font-family', 'monospace')
            .style('pointer-events', 'none');
        simulation.on('tick', () => {
            link
                .attr('x1', d => d.source.x)
                .attr('y1', d => d.source.y)
                .attr('x2', d => d.target.x)
                .attr('y2', d => d.target.y);

            node.attr('transform', d => `translate(${d.x},${d.y})`);
        });

        function dragstarted(event, d) {
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
        }

        function dragged(event, d) {
            d.fx = event.x;
            d.fy = event.y;
        }

        function dragended(event, d) {
            if (!event.active) simulation.alphaTarget(0);
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
                    <div style="font-weight: bold; margin-bottom: 5px;">${d.name}</div>
                    <div>Type: ${d.type}</div>
                    ${d.type === 'library' ? `<div>Imports: ${libraryImports[d.id] || 0}</div>` : ''}
                `);

            tooltip.style('left', (event.pageX + 10) + 'px')
                   .style('top', (event.pageY - 10) + 'px');
        }

        function hideTooltip() {
            d3.selectAll('.tooltip').remove();
        }
    }
    function filterImportExport() {
        const searchTerm = $('#import-export-search').val().toLowerCase();
        const typeFilter = $('#import-export-type-filter').value;
        const libraryFilter = $('#import-export-library-filter').value;
        const filteredImports = importExportData.imports.filter(imp => {
            const matchesSearch = !searchTerm || imp.name.toLowerCase().includes(searchTerm);
            const matchesLibrary = !libraryFilter || imp.library === libraryFilter;
            return matchesSearch && matchesLibrary;
        });
        const filteredExports = importExportData.exports.filter(exp => {
            const matchesSearch = !searchTerm || exp.name.toLowerCase().includes(searchTerm);
            return matchesSearch;
        });

        if (typeFilter === 'import') {
            renderFilteredTables(filteredImports, []);
        } else if (typeFilter === 'export') {
            renderFilteredTables([], filteredExports);
        } else {
            renderFilteredTables(filteredImports, filteredExports);
        }

        updateImportExportStats(filteredImports.length, filteredExports.length);
    }
    function renderFilteredTables(imports, exports) {
        const importsContainer = $('#imports-table');
        const exportsContainer = $('#exports-table');

        importsContainer.html(imports.map((imp, index) => `
            <div class="import-item p-3 bg-gray-800 rounded-lg border border-gray-700 hover:border-gray-600 transition cursor-pointer mb-2" 
                 data-type="import"
                 data-index="${index}"
                 data-library="${imp.library || ''}">
                <div class="flex items-center justify-between mb-1">
                    <span class="text-sm text-gray-300 font-mono">${escapeHtml(imp.name)}</span>
                    <span class="px-2 py-1 bg-orange-600 text-white rounded text-xs">IMPORT</span>
                </div>
                <div class="text-xs text-gray-400">Library: ${escapeHtml(imp.library || 'Unknown')}</div>
            </div>
        `).join(''));

        exportsContainer.html(exports.map((exp, index) => `
            <div class="export-item p-3 bg-gray-800 rounded-lg border border-gray-700 hover:border-gray-600 transition cursor-pointer mb-2" 
                 data-type="export"
                 data-index="${index}"
                 data-address="${exp.address || ''}">
                <div class="flex items-center justify-between mb-1">
                    <span class="text-sm text-gray-300 font-mono">${escapeHtml(exp.name)}</span>
                    <span class="px-2 py-1 bg-green-600 text-white rounded text-xs">EXPORT</span>
                </div>
                <div class="text-xs text-gray-400">Address: ${exp.address ? '0x' + exp.address.toString(16).toUpperCase() : 'Unknown'}</div>
            </div>
        `).join(''));
    }
    function resetImportExportFilters() {
        $('#import-export-search').val('');
        $('#import-export-type-filter').val('');
        $('#import-export-library-filter').val('');
        filterImportExport();
    }
    function updateImportExportStats(importCount, exportCount) {
        const total = importExportData.imports.length + importExportData.exports.length;
        const filteredTotal = importCount + exportCount;
        const stats = `Showing ${filteredTotal} of ${total} symbols (${importCount} imports, ${exportCount} exports)`;
        $('#import-export-stats').text(stats);
    }
    function exportImportExport() {
        if (!importExportData) return;

        const content = `IMPORTS:\n${importExportData.imports.map(imp => 
            `${imp.library || 'Unknown'}\t${imp.name}`
        ).join('\n')}\n\nEXPORTS:\n${importExportData.exports.map(exp => 
            `${exp.address || 'N/A'}\t${exp.name}`
        ).join('\n')}`;

        const blob = new Blob([content], {type: 'text/plain'});
        const url = URL.createObjectURL(blob);
        
        const link = document.createElement('a');
        link.href = url;
        link.download = `import-export-${currentJobId}.txt`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
    }
    let ieZoomScale = 1;

    function adjustIEZoom(factor) {
        ieZoomScale *= factor;
        ieZoomScale = Math.max(0.5, Math.min(3, ieZoomScale));
    }

    function resetIEZoom() {
        ieZoomScale = 1;
    }
    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
    window.importExportManager = {
        initImportExportGraph: initImportExportGraph,
        renderImportExportGraph: renderImportExportGraph
    };
});
