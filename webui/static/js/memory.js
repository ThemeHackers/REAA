$(document).ready(function() {
    let currentJobId = null;
    let memoryData = null;
    function initMemoryLayout(jobId) {
        currentJobId = jobId;
        $.get(`/api/jobs/${jobId}/memory`, function(data) {
            memoryData = data;
            renderMemoryLayout(data);
        }).fail(function(xhr) {
            console.error('Failed to load memory layout:', xhr);
            $('#memory-container').html('<div class="text-center text-gray-500 py-8">Failed to load memory layout data</div>');
        });
    }
    function renderMemoryLayout(data) {
        const container = $('#memory-container');
        container.empty();

        if (!data || !data.sections || data.sections.length === 0) {
            container.html('<div class="text-center text-gray-500 py-8">No memory layout data available</div>');
            return;
        }
        const summaryHtml = `
            <div class="memory-summary mb-6 p-4 bg-gray-800 rounded-lg border border-gray-700">
                <h4 class="text-sm font-semibold text-gray-300 mb-3">Memory Summary</h4>
                <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <div class="text-center">
                        <div class="text-2xl font-bold text-green-400">${formatSize(data.total_size)}</div>
                        <div class="text-xs text-gray-400">Total Size</div>
                    </div>
                    <div class="text-center">
                        <div class="text-2xl font-bold text-blue-400">${data.sections.length}</div>
                        <div class="text-xs text-gray-400">Sections</div>
                    </div>
                    <div class="text-center">
                        <div class="text-2xl font-bold text-purple-400">${data.base_address.toString(16).toUpperCase()}</div>
                        <div class="text-xs text-gray-400">Base Address</div>
                    </div>
                    <div class="text-center">
                        <div class="text-2xl font-bold text-yellow-400">${data.architecture || 'Unknown'}</div>
                        <div class="text-xs text-gray-400">Architecture</div>
                    </div>
                </div>
            </div>
        `;
        const codeSize = data.sections.filter(s => getSectionType(s.name) === 'code').reduce((sum, s) => sum + s.size, 0);
        const dataSize = data.sections.filter(s => getSectionType(s.name) === 'data').reduce((sum, s) => sum + s.size, 0);
        const bssSize = data.sections.filter(s => getSectionType(s.name) === 'bss').reduce((sum, s) => sum + s.size, 0);
        const rodataSize = data.sections.filter(s => getSectionType(s.name) === 'rodata').reduce((sum, s) => sum + s.size, 0);
        
        const statsHtml = `
            <div class="memory-stats mb-6 p-4 bg-gray-800 rounded-lg border border-gray-700">
                <h4 class="text-sm font-semibold text-gray-300 mb-3">Memory Usage Statistics</h4>
                <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <div class="text-center">
                        <div class="text-xl font-bold text-green-400">${formatSize(codeSize)}</div>
                        <div class="text-xs text-gray-400">Code (${((codeSize / data.total_size) * 100).toFixed(1)}%)</div>
                        <div class="w-full bg-gray-700 rounded-full h-2 mt-1">
                            <div class="bg-green-500 h-2 rounded-full" style="width: ${((codeSize / data.total_size) * 100).toFixed(1)}%"></div>
                        </div>
                    </div>
                    <div class="text-center">
                        <div class="text-xl font-bold text-blue-400">${formatSize(dataSize)}</div>
                        <div class="text-xs text-gray-400">Data (${((dataSize / data.total_size) * 100).toFixed(1)}%)</div>
                        <div class="w-full bg-gray-700 rounded-full h-2 mt-1">
                            <div class="bg-blue-500 h-2 rounded-full" style="width: ${((dataSize / data.total_size) * 100).toFixed(1)}%"></div>
                        </div>
                    </div>
                    <div class="text-center">
                        <div class="text-xl font-bold text-yellow-400">${formatSize(bssSize)}</div>
                        <div class="text-xs text-gray-400">BSS (${((bssSize / data.total_size) * 100).toFixed(1)}%)</div>
                        <div class="w-full bg-gray-700 rounded-full h-2 mt-1">
                            <div class="bg-yellow-500 h-2 rounded-full" style="width: ${((bssSize / data.total_size) * 100).toFixed(1)}%"></div>
                        </div>
                    </div>
                    <div class="text-center">
                        <div class="text-xl font-bold text-purple-400">${formatSize(rodataSize)}</div>
                        <div class="text-xs text-gray-400">Read-Only (${((rodataSize / data.total_size) * 100).toFixed(1)}%)</div>
                        <div class="w-full bg-gray-700 rounded-full h-2 mt-1">
                            <div class="bg-purple-500 h-2 rounded-full" style="width: ${((rodataSize / data.total_size) * 100).toFixed(1)}%"></div>
                        </div>
                    </div>
                </div>
            </div>
        `;
        const sectionsHtml = data.sections.map((section, index) => {
            const sectionType = getSectionType(section.name);
            const colorClass = getSectionColor(sectionType);
            const percentage = ((section.size / data.total_size) * 100).toFixed(1);
            const permissions = getPermissionBadges(section.permissions);

            return `
                <div class="memory-section mb-4 p-4 bg-gray-800 rounded-lg border border-gray-700 hover:border-gray-600 transition cursor-pointer" data-section="${section.name}">
                    <div class="flex items-center justify-between mb-2">
                        <div class="flex items-center gap-2">
                            <div class="w-3 h-3 rounded-full ${colorClass}"></div>
                            <span class="text-sm font-medium text-gray-300">${section.name}</span>
                        </div>
                        <div class="flex items-center gap-2">
                            ${permissions}
                        </div>
                    </div>
                    <div class="grid grid-cols-3 gap-4 text-xs">
                        <div>
                            <div class="text-gray-500">Address</div>
                            <div class="font-mono text-gray-300">0x${section.address.toString(16).toUpperCase()}</div>
                        </div>
                        <div>
                            <div class="text-gray-500">Size</div>
                            <div class="text-gray-300">${formatSize(section.size)} (${percentage}%)</div>
                        </div>
                        <div>
                            <div class="text-gray-500">Type</div>
                            <div class="text-gray-300 capitalize">${sectionType}</div>
                        </div>
                    </div>
                    <div class="mt-2">
                        <div class="w-full bg-gray-700 rounded-full h-2">
                            <div class="${colorClass} h-2 rounded-full" style="width: ${percentage}%"></div>
                        </div>
                    </div>
                </div>
            `;
        }).join('');
        const memoryMapHtml = `
            <div class="memory-map mt-6 p-4 bg-gray-800 rounded-lg border border-gray-700">
                <div class="flex items-center justify-between mb-3">
                    <h4 class="text-sm font-semibold text-gray-300">Memory Address Space</h4>
                    <div class="flex gap-2">
                        <button id="zoom-in" class="px-2 py-1 bg-gray-700 hover:bg-gray-600 text-gray-300 rounded text-xs">+</button>
                        <button id="zoom-out" class="px-2 py-1 bg-gray-700 hover:bg-gray-600 text-gray-300 rounded text-xs">-</button>
                        <button id="reset-zoom" class="px-2 py-1 bg-gray-700 hover:bg-gray-600 text-gray-300 rounded text-xs">Reset</button>
                    </div>
                </div>
                <div class="memory-map-visual relative h-16 bg-gray-900 rounded-lg overflow-hidden" id="memory-map-container">
                    ${data.sections.map((section, index) => {
                        const offset = ((section.address - data.base_address) / data.total_size) * 100;
                        const width = Math.max(0.5, (section.size / data.total_size) * 100);
                        const colorClass = getSectionColor(getSectionType(section.name));
                        const permissionIndicator = getPermissionIndicator(section.permissions);
                        
                        return `
                            <div class="memory-map-section absolute ${colorClass} ${permissionIndicator} hover:opacity-100 transition cursor-pointer border border-gray-600"
                                 style="left: ${offset}%; width: ${width}%; height: 100%;"
                                 title="${section.name}: ${formatSize(section.size)} @ 0x${section.address.toString(16).toUpperCase()} (${section.permissions || 'N/A'})"
                                 data-section="${section.name}">
                            </div>
                        `;
                    }).join('')}
                </div>
                <div class="flex justify-between text-xs text-gray-500 mt-2 font-mono">
                    <span>0x${data.base_address.toString(16).toUpperCase()}</span>
                    <span>0x${(data.base_address + data.total_size).toString(16).toUpperCase()}</span>
                </div>
            </div>
        `;
        const stackHeapHtml = `
            <div class="stack-heap mt-6 p-4 bg-gray-800 rounded-lg border border-gray-700">
                <h4 class="text-sm font-semibold text-gray-300 mb-3">Stack & Heap Visualization</h4>
                <div class="grid grid-cols-2 gap-4">
                    <div>
                        <h5 class="text-xs font-medium text-red-400 mb-2">Stack Region</h5>
                        <div class="bg-gray-900 rounded-lg p-3 h-32 relative">
                            <div class="absolute inset-0 flex flex-col justify-end">
                                <div class="bg-red-600 bg-opacity-30 border border-red-500 rounded-t p-2 text-xs text-gray-300">
                                    <div class="font-mono">High Addresses</div>
                                    <div class="text-gray-400">Return addresses, local variables</div>
                                </div>
                                <div class="flex-1 bg-gradient-to-b from-red-600/20 to-transparent"></div>
                                <div class="bg-red-600 bg-opacity-30 border border-red-500 rounded-b p-2 text-xs text-gray-300">
                                    <div class="font-mono">Stack Pointer (SP)</div>
                                    <div class="text-gray-400">Current stack frame</div>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div>
                        <h5 class="text-xs font-medium text-orange-400 mb-2">Heap Region</h5>
                        <div class="bg-gray-900 rounded-lg p-3 h-32 relative">
                            <div class="absolute inset-0 flex flex-col">
                                <div class="bg-orange-600 bg-opacity-30 border border-orange-500 rounded p-2 text-xs text-gray-300 mb-2">
                                    <div class="font-mono">Heap Start</div>
                                    <div class="text-gray-400">Dynamic allocations</div>
                                </div>
                                <div class="flex-1 bg-gradient-to-b from-orange-600/20 to-orange-600/10 rounded border border-orange-500/30 p-2">
                                    <div class="text-xs text-gray-400 mb-1">Allocated blocks:</div>
                                    <div class="space-y-1">
                                        <div class="bg-orange-600 bg-opacity-40 rounded h-2"></div>
                                        <div class="bg-orange-600 bg-opacity-60 rounded h-3"></div>
                                        <div class="bg-orange-600 bg-opacity-30 rounded h-2"></div>
                                        <div class="bg-orange-600 bg-opacity-50 rounded h-4"></div>
                                    </div>
                                </div>
                                <div class="bg-orange-600 bg-opacity-30 border border-orange-500 rounded p-2 text-xs text-gray-300 mt-2">
                                    <div class="font-mono">Heap End</div>
                                    <div class="text-gray-400">Free space</div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
        const hexViewerHtml = `
            <div class="hex-viewer mt-6 p-4 bg-gray-800 rounded-lg border border-gray-700">
                <div class="flex items-center justify-between mb-3">
                    <h4 class="text-sm font-semibold text-gray-300">Hex Dump Viewer</h4>
                    <div class="flex gap-2">
                        <input type="text" id="hex-address" placeholder="Address (hex)" 
                               class="px-2 py-1 bg-gray-700 border border-gray-600 rounded text-gray-200 text-xs w-32 focus:outline-none focus:border-blue-500">
                        <button id="hex-goto" class="px-2 py-1 bg-blue-600 hover:bg-blue-700 text-white rounded text-xs">Go</button>
                        <button id="hex-search" class="px-2 py-1 bg-green-600 hover:bg-green-700 text-white rounded text-xs">Search Pattern</button>
                        <button id="hex-save-snapshot" class="px-2 py-1 bg-yellow-600 hover:bg-yellow-700 text-white rounded text-xs">Save Snapshot</button>
                    </div>
                </div>
                <div id="hex-search-panel" class="hidden mb-3 p-3 bg-gray-900 rounded border border-gray-700">
                    <div class="flex gap-2 items-center">
                        <input type="text" id="hex-pattern" placeholder="Byte pattern (e.g., 48 65 6c 6c 6f) or regex" 
                               class="flex-1 px-2 py-1 bg-gray-700 border border-gray-600 rounded text-gray-200 text-xs focus:outline-none focus:border-blue-500">
                        <select id="hex-search-type" class="px-2 py-1 bg-gray-700 border border-gray-600 rounded text-gray-200 text-xs">
                            <option value="hex">Hex Bytes</option>
                            <option value="regex">Regex</option>
                            <option value="ascii">ASCII</option>
                        </select>
                        <button id="hex-search-btn" class="px-2 py-1 bg-green-600 hover:bg-green-700 text-white rounded text-xs">Search</button>
                        <button id="hex-search-close" class="px-2 py-1 bg-gray-600 hover:bg-gray-700 text-white rounded text-xs">✕</button>
                    </div>
                    <div id="hex-search-results" class="mt-2 text-xs text-gray-400"></div>
                </div>
                <div id="hex-content" class="bg-gray-900 rounded p-3 font-mono text-xs text-gray-300 overflow-x-auto max-h-64 overflow-y-auto">
                    <div class="text-gray-500 text-center py-4">Select a section to view hex dump</div>
                </div>
                <div class="flex justify-between mt-2">
                    <button id="hex-prev" class="px-2 py-1 bg-gray-700 hover:bg-gray-600 text-gray-300 rounded text-xs">Previous</button>
                    <span id="hex-offset" class="text-xs text-gray-400">Offset: 0x0</span>
                    <button id="hex-next" class="px-2 py-1 bg-gray-700 hover:bg-gray-600 text-gray-300 rounded text-xs">Next</button>
                </div>
            </div>
        `;

        const diffViewHtml = `
            <div class="memory-diff-view mt-6 p-4 bg-gray-800 rounded-lg border border-gray-700">
                <div class="flex items-center justify-between mb-3">
                    <h4 class="text-sm font-semibold text-gray-300">Memory Diff View</h4>
                    <div class="flex gap-2">
                        <select id="diff-snapshot-1" class="px-2 py-1 bg-gray-700 border border-gray-600 rounded text-gray-200 text-xs">
                            <option value="">Select Snapshot 1</option>
                        </select>
                        <select id="diff-snapshot-2" class="px-2 py-1 bg-gray-700 border border-gray-600 rounded text-gray-200 text-xs">
                            <option value="">Select Snapshot 2</option>
                        </select>
                        <button id="diff-compare" class="px-2 py-1 bg-blue-600 hover:bg-blue-700 text-white rounded text-xs">Compare</button>
                        <button id="diff-clear" class="px-2 py-1 bg-gray-600 hover:bg-gray-700 text-white rounded text-xs">Clear</button>
                    </div>
                </div>
                <div id="diff-content" class="bg-gray-900 rounded p-3 font-mono text-xs max-h-64 overflow-y-auto">
                    <div class="text-gray-500 text-center py-4">Select two snapshots to compare</div>
                </div>
            </div>
        `;

        const annotationHtml = `
            <div class="memory-annotation mt-6 p-4 bg-gray-800 rounded-lg border border-gray-700">
                <div class="flex items-center justify-between mb-3">
                    <h4 class="text-sm font-semibold text-gray-300">Region Annotations</h4>
                    <button id="annotation-add" class="px-2 py-1 bg-green-600 hover:bg-green-700 text-white rounded text-xs">Add Annotation</button>
                </div>
                <div id="annotation-list" class="space-y-2 max-h-48 overflow-y-auto">
                    <div class="text-gray-500 text-center py-2 text-xs">No annotations</div>
                </div>
            </div>
        `;

        const heatMapHtml = `
            <div class="memory-heatmap mt-6 p-4 bg-gray-800 rounded-lg border border-gray-700">
                <div class="flex items-center justify-between mb-3">
                    <h4 class="text-sm font-semibold text-gray-300">Access Heat Map</h4>
                    <div class="flex gap-2 items-center">
                        <label class="text-xs text-gray-400">Simulate Access:</label>
                        <button id="heatmap-simulate" class="px-2 py-1 bg-blue-600 hover:bg-blue-700 text-white rounded text-xs">Simulate</button>
                        <button id="heatmap-clear" class="px-2 py-1 bg-gray-600 hover:bg-gray-700 text-white rounded text-xs">Clear</button>
                    </div>
                </div>
                <div id="heatmap-legend" class="flex gap-2 mb-2 text-xs">
                    <span class="flex items-center gap-1"><div class="w-3 h-3 bg-green-500"></div> Low</span>
                    <span class="flex items-center gap-1"><div class="w-3 h-3 bg-yellow-500"></div> Medium</span>
                    <span class="flex items-center gap-1"><div class="w-3 h-3 bg-red-500"></div> High</span>
                </div>
                <div id="heatmap-content" class="bg-gray-900 rounded p-3 h-32 overflow-hidden">
                    <div class="text-gray-500 text-center py-4 text-xs">Click "Simulate" to generate heat map</div>
                </div>
            </div>
        `;

        const legendHtml = `
            <div class="memory-legend mt-6 p-4 bg-gray-800 rounded-lg border border-gray-700">
                <h4 class="text-sm font-semibold text-gray-300 mb-3">Section Types</h4>
                <div class="grid grid-cols-2 md:grid-cols-4 gap-3">
                    ${[
                        { type: 'code', color: 'bg-green-500', label: 'Code (.text)' },
                        { type: 'data', color: 'bg-blue-500', label: 'Data (.data)' },
                        { type: 'bss', color: 'bg-yellow-500', label: 'BSS (.bss)' },
                        { type: 'rodata', color: 'bg-purple-500', label: 'Read-Only (.rodata)' },
                        { type: 'stack', color: 'bg-red-500', label: 'Stack' },
                        { type: 'heap', color: 'bg-orange-500', label: 'Heap' },
                        { type: 'import', color: 'bg-pink-500', label: 'Import (.idata)' },
                        { type: 'export', color: 'bg-cyan-500', label: 'Export (.edata)' }
                    ].map(item => `
                        <div class="flex items-center gap-2">
                            <div class="w-3 h-3 rounded-full ${item.color}"></div>
                            <span class="text-xs text-gray-400">${item.label}</span>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;

        container.html(`
            ${summaryHtml}
            ${statsHtml}
            <div class="memory-sections">
                ${sectionsHtml}
            </div>
            ${memoryMapHtml}
            ${stackHeapHtml}
            ${hexViewerHtml}
            ${diffViewHtml}
            ${annotationHtml}
            ${heatMapHtml}
            ${legendHtml}
        `);
        $('.memory-section').on('click', function() {
            const sectionName = $(this).data('section');
            showSectionDetails(sectionName);
        });
        $('.memory-map-section').on('click', function() {
            const sectionName = $(this).data('section');
            showSectionDetails(sectionName);
        });
        $('#zoom-in').on('click', () => adjustMemoryMapZoom(1.2));
        $('#zoom-out').on('click', () => adjustMemoryMapZoom(0.8));
        $('#reset-zoom').on('click', () => resetMemoryMapZoom());
        setupHexViewerHandlers();
    }
    function getPermissionBadges(permissions) {
        if (!permissions) return '';
        
        const badges = [];
        if (permissions.includes('R')) {
            badges.push('<span class="px-2 py-1 bg-green-600 text-white rounded text-xs font-bold border border-green-400">R</span>');
        }
        if (permissions.includes('W')) {
            badges.push('<span class="px-2 py-1 bg-red-600 text-white rounded text-xs font-bold border border-red-400">W</span>');
        }
        if (permissions.includes('X')) {
            badges.push('<span class="px-2 py-1 bg-blue-600 text-white rounded text-xs font-bold border border-blue-400">X</span>');
        }
        
        return badges.join('');
    }
    function getPermissionIndicator(permissions) {
        if (!permissions) return 'bg-gray-600';
        
        const hasR = permissions.includes('R');
        const hasW = permissions.includes('W');
        const hasX = permissions.includes('X');
        
        if (hasR && hasW && hasX) return 'bg-gradient-to-r from-green-500 via-red-500 to-blue-500';
        if (hasR && hasW) return 'bg-gradient-to-r from-green-500 to-red-500';
        if (hasR && hasX) return 'bg-gradient-to-r from-green-500 to-blue-500';
        if (hasW && hasX) return 'bg-gradient-to-r from-red-500 to-blue-500';
        if (hasR) return 'bg-green-500';
        if (hasW) return 'bg-red-500';
        if (hasX) return 'bg-blue-500';
        
        return 'bg-gray-600';
    }
    let memoryMapScale = 1;

    function adjustMemoryMapZoom(factor) {
        memoryMapScale *= factor;
        memoryMapScale = Math.max(1, Math.min(10, memoryMapScale));
        $('#memory-map-container').css('width', `${memoryMapScale * 100}%`);
    }

    function resetMemoryMapZoom() {
        memoryMapScale = 1;
        $('#memory-map-container').css('width', '100%');
    }
    function getSectionType(name) {
        if (!name) return 'unknown';
        const lowerName = name.toLowerCase();
        if (lowerName.includes('.text') || lowerName.includes('code')) return 'code';
        if (lowerName.includes('.data')) return 'data';
        if (lowerName.includes('.bss')) return 'bss';
        if (lowerName.includes('.rodata') || lowerName.includes('rdata')) return 'rodata';
        if (lowerName.includes('.idata') || lowerName.includes('import')) return 'import';
        if (lowerName.includes('.edata') || lowerName.includes('export')) return 'export';
        if (lowerName.includes('stack')) return 'stack';
        if (lowerName.includes('heap')) return 'heap';
        return 'unknown';
    }
    function getSectionColor(type) {
        const colors = {
            'code': 'bg-green-500',
            'data': 'bg-blue-500',
            'bss': 'bg-yellow-500',
            'rodata': 'bg-purple-500',
            'import': 'bg-pink-500',
            'export': 'bg-cyan-500',
            'stack': 'bg-red-500',
            'heap': 'bg-orange-500',
            'unknown': 'bg-gray-500'
        };
        return colors[type] || colors.unknown;
    }
    function formatSize(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }
    function showSectionDetails(sectionName) {
        const section = memoryData.sections.find(s => s.name === sectionName);
        if (!section) return;

        const detailsHtml = `
            <div class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50" id="section-details-modal">
                <div class="bg-gray-800 rounded-lg p-6 max-w-lg w-full mx-4 border border-gray-700">
                    <div class="flex justify-between items-center mb-4">
                        <h3 class="text-lg font-semibold text-gray-300">${section.name}</h3>
                        <button class="text-gray-400 hover:text-white" onclick="$('#section-details-modal').remove()">✕</button>
                    </div>
                    <div class="space-y-3">
                        <div>
                            <div class="text-sm text-gray-500">Address</div>
                            <div class="font-mono text-gray-300">0x${section.address.toString(16).toUpperCase()}</div>
                        </div>
                        <div>
                            <div class="text-sm text-gray-500">Size</div>
                            <div class="text-gray-300">${formatSize(section.size)}</div>
                        </div>
                        <div>
                            <div class="text-sm text-gray-500">Permissions</div>
                            <div class="text-gray-300">${section.permissions || 'N/A'}</div>
                        </div>
                        <div>
                            <div class="text-sm text-gray-500">Type</div>
                            <div class="text-gray-300 capitalize">${getSectionType(section.name)}</div>
                        </div>
                    </div>
                </div>
            </div>
        `;

        $('body').append(detailsHtml);
    }
    window.memoryLayoutManager = {
        initMemoryLayout: initMemoryLayout,
        renderMemoryLayout: renderMemoryLayout
    };
    let hexViewerState = {
        currentSection: null,
        offset: 0,
        bytesPerLine: 16,
        searchResults: [],
        searchIndex: 0
    };
    function setupHexViewerHandlers() {
        $('#hex-search').on('click', function() {
            $('#hex-search-panel').toggleClass('hidden');
        });
        $('#hex-search-close').on('click', function() {
            $('#hex-search-panel').addClass('hidden');
        });
        $('#hex-search-btn').on('click', performHexSearch);
        $('#hex-goto').on('click', gotoHexAddress);
        $('#hex-prev').on('click', () => navigateHex(-1));
        $('#hex-next').on('click', () => navigateHex(1));
        $('#hex-save-snapshot').on('click', saveMemorySnapshot);
        $('#diff-compare').on('click', compareSnapshots);
        $('#diff-clear').on('click', clearDiff);
        $('#annotation-add').on('click', addRegionAnnotation);
        $('#heatmap-simulate').on('click', simulateHeatMap);
        $('#heatmap-clear').on('click', clearHeatMap);
        loadSnapshots();
        loadAnnotations();
    }
    function performHexSearch() {
        const pattern = $('#hex-pattern').val();
        const searchType = $('#hex-search-type').val();
        
        if (!hexViewerState.currentSection) {
            $('#hex-search-results').text('Please select a section first');
            return;
        }
        
        $.get(`/api/jobs/${currentJobId}/memory/${hexViewerState.currentSection}/hex`, function(hexData) {
            const results = [];
            const bytes = hexData.bytes || [];
            
            if (searchType === 'hex') {
                const patternBytes = pattern.split(/\s+/).map(b => parseInt(b, 16));
                for (let i = 0; i <= bytes.length - patternBytes.length; i++) {
                    let match = true;
                    for (let j = 0; j < patternBytes.length; j++) {
                        if (bytes[i + j] !== patternBytes[j]) {
                            match = false;
                            break;
                        }
                    }
                    if (match) results.push(i);
                }
            } else if (searchType === 'ascii') {
                for (let i = 0; i <= bytes.length - pattern.length; i++) {
                    let match = true;
                    for (let j = 0; j < pattern.length; j++) {
                        if (bytes[i + j] !== pattern.charCodeAt(j)) {
                            match = false;
                            break;
                        }
                    }
                    if (match) results.push(i);
                }
            } else if (searchType === 'regex') {
                const text = bytes.map(b => String.fromCharCode(b)).join('');
                const regex = new RegExp(pattern, 'g');
                let match;
                while ((match = regex.exec(text)) !== null) {
                    results.push(match.index);
                }
            }
            
            hexViewerState.searchResults = results;
            hexViewerState.searchIndex = 0;
            
            if (results.length > 0) {
                $('#hex-search-results').text(`Found ${results.length} matches. Use Next/Prev to navigate.`);
                hexViewerState.offset = results[0];
                renderHexDump(hexData);
            } else {
                $('#hex-search-results').text('No matches found');
            }
        }).fail(function() {
            $('#hex-search-results').text('Failed to search memory');
        });
    }
    function gotoHexAddress() {
        const addressStr = $('#hex-address').val();
        const address = parseInt(addressStr, 16);
        
        if (isNaN(address)) {
            showToast('Invalid address', 'error');
            return;
        }
        
        if (!hexViewerState.currentSection) {
            showToast('Please select a section first', 'warning');
            return;
        }
        
        const section = memoryData.sections.find(s => s.name === hexViewerState.currentSection);
        if (!section) return;
        
        const relativeOffset = address - section.address;
        if (relativeOffset < 0 || relativeOffset >= section.size) {
            showToast('Address outside section bounds', 'error');
            return;
        }
        
        hexViewerState.offset = relativeOffset;
        loadHexDump();
    }
    function navigateHex(direction) {
        if (hexViewerState.searchResults.length > 0) {
            hexViewerState.searchIndex += direction;
            if (hexViewerState.searchIndex < 0) hexViewerState.searchIndex = hexViewerState.searchResults.length - 1;
            if (hexViewerState.searchIndex >= hexViewerState.searchResults.length) hexViewerState.searchIndex = 0;
            hexViewerState.offset = hexViewerState.searchResults[hexViewerState.searchIndex];
            loadHexDump();
        } else {
            hexViewerState.offset += direction * hexViewerState.bytesPerLine;
            loadHexDump();
        }
    }
    function loadHexDump() {
        if (!hexViewerState.currentSection) return;
        
        $.get(`/api/jobs/${currentJobId}/memory/${hexViewerState.currentSection}/hex`, function(hexData) {
            renderHexDump(hexData);
        }).fail(function() {
            $('#hex-content').html('<div class="text-red-400 text-center py-4">Failed to load hex dump</div>');
        });
    }
    function renderHexDump(hexData) {
        const bytes = hexData.bytes || [];
        const startOffset = Math.max(0, hexViewerState.offset);
        const endOffset = Math.min(bytes.length, startOffset + 256);
        const displayBytes = bytes.slice(startOffset, endOffset);
        
        let html = '';
        for (let i = 0; i < displayBytes.length; i += hexViewerState.bytesPerLine) {
            const lineBytes = displayBytes.slice(i, i + hexViewerState.bytesPerLine);
            const offset = startOffset + i;
            
            const hexPart = lineBytes.map(b => b.toString(16).padStart(2, '0')).join(' ');
            const asciiPart = lineBytes.map(b => (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.').join('');
            
            html += `<div class="flex hover:bg-gray-800">
                <span class="text-blue-400 w-20">0x${offset.toString(16).padStart(8, '0')}</span>
                <span class="text-green-400 w-48">${hexPart.padEnd(47, ' ')}</span>
                <span class="text-gray-300">${asciiPart}</span>
            </div>`;
        }
        
        $('#hex-content').html(html || '<div class="text-gray-500 text-center py-4">No data available</div>');
        $('#hex-offset').text(`Offset: 0x${startOffset.toString(16)} / Total: 0x${bytes.length.toString(16)}`);
    }
    let memorySnapshots = [];
    function saveMemorySnapshot() {
        if (!hexViewerState.currentSection) {
            showToast('Please select a section first', 'warning');
            return;
        }
        
        const snapshotName = prompt('Enter snapshot name:') || `Snapshot ${memorySnapshots.length + 1}`;
        
        $.get(`/api/jobs/${currentJobId}/memory/${hexViewerState.currentSection}/hex`, function(hexData) {
            const snapshot = {
                id: 'snapshot_' + Date.now(),
                name: snapshotName,
                section: hexViewerState.currentSection,
                bytes: hexData.bytes,
                timestamp: Date.now()
            };
            
            memorySnapshots.push(snapshot);
            localStorage.setItem(`memory_snapshots_${currentJobId}`, JSON.stringify(memorySnapshots));
            loadSnapshots();
            showToast('Snapshot saved successfully', 'success');
        }).fail(function() {
            showToast('Failed to save snapshot', 'error');
        });
    }
    function loadSnapshots() {
        const saved = localStorage.getItem(`memory_snapshots_${currentJobId}`);
        if (saved) {
            memorySnapshots = JSON.parse(saved);
        }
        
        const select1 = $('#diff-snapshot-1');
        const select2 = $('#diff-snapshot-2');
        
        select1.empty();
        select2.empty();
        select1.append('<option value="">Select Snapshot 1</option>');
        select2.append('<option value="">Select Snapshot 2</option>');
        
        memorySnapshots.forEach(snapshot => {
            const option = `<option value="${snapshot.id}">${snapshot.name} (${new Date(snapshot.timestamp).toLocaleString()})</option>`;
            select1.append(option);
            select2.append(option);
        });
    }
    function compareSnapshots() {
        const snapshot1Id = $('#diff-snapshot-1').val();
        const snapshot2Id = $('#diff-snapshot-2').val();
        
        if (!snapshot1Id || !snapshot2Id) {
            showToast('Please select two snapshots to compare', 'warning');
            return;
        }
        
        if (snapshot1Id === snapshot2Id) {
            showToast('Please select different snapshots', 'warning');
            return;
        }
        
        const snapshot1 = memorySnapshots.find(s => s.id === snapshot1Id);
        const snapshot2 = memorySnapshots.find(s => s.id === snapshot2Id);
        
        if (!snapshot1 || !snapshot2) {
            showToast('Snapshots not found', 'error');
            return;
        }
        
        const bytes1 = snapshot1.bytes || [];
        const bytes2 = snapshot2.bytes || [];
        const maxLength = Math.max(bytes1.length, bytes2.length);
        
        let html = '';
        let diffCount = 0;
        
        for (let i = 0; i < maxLength; i += 16) {
            const lineBytes1 = bytes1.slice(i, i + 16);
            const lineBytes2 = bytes2.slice(i, i + 16);
            const offset = i;
            
            const hexPart1 = lineBytes1.map(b => b.toString(16).padStart(2, '0')).join(' ');
            const hexPart2 = lineBytes2.map(b => b.toString(16).padStart(2, '0')).join(' ');
            
            const hasDiff = lineBytes1.some((b, idx) => b !== lineBytes2[idx]);
            if (hasDiff) diffCount++;
            
            const bgClass = hasDiff ? 'bg-red-900/30' : '';
            
            html += `<div class="flex ${bgClass}">
                <span class="text-blue-400 w-20">0x${offset.toString(16).padStart(8, '0')}</span>
                <span class="text-green-400 w-48">${hexPart1.padEnd(47, ' ')}</span>
                <span class="text-yellow-400 w-48">${hexPart2.padEnd(47, ' ')}</span>
            </div>`;
        }
        
        $('#diff-content').html(html || '<div class="text-gray-500 text-center py-4">No differences found</div>');
        showToast(`Found ${diffCount} differing lines`, diffCount > 0 ? 'info' : 'success');
    }
    function clearDiff() {
        $('#diff-content').html('<div class="text-gray-500 text-center py-4">Select two snapshots to compare</div>');
        $('#diff-snapshot-1').val('');
        $('#diff-snapshot-2').val('');
    }
    let regionAnnotations = [];
    function addRegionAnnotation() {
        if (!memoryData || !memoryData.sections) {
            showToast('No memory data available', 'warning');
            return;
        }
        
        const sectionName = prompt('Enter section name (e.g., .text, .data):');
        if (!sectionName) return;
        
        const section = memoryData.sections.find(s => s.name === sectionName);
        if (!section) {
            showToast('Section not found', 'error');
            return;
        }
        
        const annotation = {
            id: 'annotation_' + Date.now(),
            section: sectionName,
            address: section.address,
            size: section.size,
            note: prompt('Enter annotation note:') || 'No note',
            color: prompt('Enter color (red, blue, green, yellow, purple):') || 'blue',
            timestamp: Date.now()
        };
        
        regionAnnotations.push(annotation);
        localStorage.setItem(`memory_annotations_${currentJobId}`, JSON.stringify(regionAnnotations));
        renderAnnotations();
        showToast('Annotation added successfully', 'success');
    }
    function loadAnnotations() {
        const saved = localStorage.getItem(`memory_annotations_${currentJobId}`);
        if (saved) {
            regionAnnotations = JSON.parse(saved);
            renderAnnotations();
        }
    }
    function renderAnnotations() {
        const container = $('#annotation-list');
        
        if (regionAnnotations.length === 0) {
            container.html('<div class="text-gray-500 text-center py-2 text-xs">No annotations</div>');
            return;
        }
        
        container.html(regionAnnotations.map(ann => `
            <div class="flex items-center justify-between p-2 bg-gray-900 rounded border-l-4 border-${ann.color}-500">
                <div class="flex-1">
                    <div class="text-xs font-medium text-gray-300">${ann.section}</div>
                    <div class="text-xs text-gray-400">0x${ann.address.toString(16)} - ${ann.note}</div>
                </div>
                <button class="text-red-400 hover:text-red-300 text-xs" onclick="deleteAnnotation('${ann.id}')">✕</button>
            </div>
        `).join(''));
    }
    window.deleteAnnotation = function(id) {
        regionAnnotations = regionAnnotations.filter(a => a.id !== id);
        localStorage.setItem(`memory_annotations_${currentJobId}`, JSON.stringify(regionAnnotations));
        renderAnnotations();
    };
    let heatMapData = [];
    function simulateHeatMap() {
        if (!memoryData || !memoryData.sections) {
            showToast('No memory data available', 'warning');
            return;
        }
        
        heatMapData = memoryData.sections.map(section => ({
            name: section.name,
            address: section.address,
            size: section.size,
            accessCount: Math.floor(Math.random() * 1000),
            lastAccess: Date.now() - Math.floor(Math.random() * 86400000)
        }));
        
        renderHeatMap();
        showToast('Heat map simulated successfully', 'success');
    }
    function renderHeatMap() {
        const container = $('#heatmap-content');
        
        if (heatMapData.length === 0) {
            container.html('<div class="text-gray-500 text-center py-4 text-xs">No heat map data</div>');
            return;
        }
        
        const maxAccess = Math.max(...heatMapData.map(d => d.accessCount));
        const totalSize = heatMapData.reduce((sum, d) => sum + d.size, 0);
        
        let html = '<div class="flex flex-wrap gap-1">';
        heatMapData.forEach(data => {
            const intensity = data.accessCount / maxAccess;
            const widthPercent = (data.size / totalSize) * 100;
            
            let colorClass;
            if (intensity < 0.33) {
                colorClass = 'bg-green-500';
            } else if (intensity < 0.66) {
                colorClass = 'bg-yellow-500';
            } else {
                colorClass = 'bg-red-500';
            }
            
            html += `
                <div class="relative ${colorClass} hover:opacity-80 cursor-pointer" 
                     style="width: ${widthPercent}%; height: 100%; min-width: 20px;"
                     title="${data.name}: ${data.accessCount} accesses">
                    <div class="absolute inset-0 flex items-center justify-center text-xs text-white font-bold opacity-0 hover:opacity-100">
                        ${data.name}
                    </div>
                </div>
            `;
        });
        html += '</div>';
        
        container.html(html);
    }
    function clearHeatMap() {
        heatMapData = [];
        $('#heatmap-content').html('<div class="text-gray-500 text-center py-4 text-xs">Click "Simulate" to generate heat map</div>');
        showToast('Heat map cleared', 'info');
    }
});
