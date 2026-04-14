$(document).ready(function() {
    let currentJobId = null;
    let stringsData = null;
    function initStringAnalysis(jobId) {
        currentJobId = jobId;
        $.get(`/api/jobs/${jobId}/strings`, function(data) {
            stringsData = data;
            renderStringAnalysis(data);
        }).fail(function(xhr) {
            console.error('Failed to load strings:', xhr);
            $('#strings-container').html('<div class="text-center text-gray-500 py-8">Failed to load strings data</div>');
        });
    }
    function renderStringAnalysis(data) {
        const container = $('#strings-container');
        container.empty();

        if (!data || !data.strings || data.strings.length === 0) {
            container.html('<div class="text-center text-gray-500 py-8">No strings data available</div>');
            return;
        }

        const strings = data.strings;
        const totalStrings = strings.length;
        const asciiStrings = strings.filter(s => s.type === 'ascii').length;
        const unicodeStrings = strings.filter(s => s.type === 'unicode').length;
        const totalLength = strings.reduce((sum, s) => sum + s.length, 0);
        const avgLength = (totalLength / totalStrings).toFixed(1);
        const summaryHtml = `
            <div class="strings-summary mb-6 p-4 bg-gray-800 rounded-lg border border-gray-700">
                <h4 class="text-sm font-semibold text-gray-300 mb-3">String Analysis Summary</h4>
                <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <div class="text-center">
                        <div class="text-2xl font-bold text-green-400">${totalStrings}</div>
                        <div class="text-xs text-gray-400">Total Strings</div>
                    </div>
                    <div class="text-center">
                        <div class="text-2xl font-bold text-blue-400">${asciiStrings}</div>
                        <div class="text-xs text-gray-400">ASCII (${((asciiStrings / totalStrings) * 100).toFixed(1)}%)</div>
                    </div>
                    <div class="text-center">
                        <div class="text-2xl font-bold text-purple-400">${unicodeStrings}</div>
                        <div class="text-xs text-gray-400">Unicode (${((unicodeStrings / totalStrings) * 100).toFixed(1)}%)</div>
                    </div>
                    <div class="text-center">
                        <div class="text-2xl font-bold text-yellow-400">${avgLength}</div>
                        <div class="text-xs text-gray-400">Avg Length</div>
                    </div>
                </div>
            </div>
        `;
        const controlsHtml = `
            <div class="strings-controls mb-6 p-4 bg-gray-800 rounded-lg border border-gray-700">
                <div class="flex flex-wrap gap-4 items-center">
                    <div class="flex-1 min-w-[200px]">
                        <input type="text" id="strings-search" placeholder="Search strings..." 
                               class="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-gray-200 text-sm focus:outline-none focus:border-blue-500">
                    </div>
                    <div>
                        <select id="strings-type-filter" class="px-3 py-2 bg-gray-700 border border-gray-600 rounded text-gray-200 text-sm focus:outline-none focus:border-blue-500">
                            <option value="">All Types</option>
                            <option value="ascii">ASCII</option>
                            <option value="unicode">Unicode</option>
                        </select>
                    </div>
                    <div>
                        <select id="strings-min-length" class="px-3 py-2 bg-gray-700 border border-gray-600 rounded text-gray-200 text-sm focus:outline-none focus:border-blue-500">
                            <option value="0">Min Length: Any</option>
                            <option value="4">4+ chars</option>
                            <option value="8">8+ chars</option>
                            <option value="16">16+ chars</option>
                            <option value="32">32+ chars</option>
                        </select>
                    </div>
                    <div class="flex gap-2">
                        <button id="strings-reset" class="px-3 py-2 bg-gray-700 hover:bg-gray-600 text-gray-200 rounded text-sm">Reset</button>
                        <button id="strings-export" class="px-3 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded text-sm">Export</button>
                    </div>
                </div>
                <div id="strings-stats" class="text-xs text-gray-400 mt-2"></div>
            </div>
        `;
        const stringsHtml = `
            <div class="strings-list">
                <h4 class="text-sm font-semibold text-gray-300 mb-3">Strings (${strings.length})</h4>
                <div class="space-y-2 max-h-96 overflow-y-auto" id="strings-table">
                    ${strings.map((str, index) => `
                        <div class="string-item p-3 bg-gray-800 rounded-lg border border-gray-700 hover:border-gray-600 transition cursor-pointer" 
                             data-string-index="${index}"
                             data-type="${str.type}"
                             data-length="${str.length}"
                             data-address="${str.address}">
                            <div class="flex items-center justify-between mb-1">
                                <div class="flex items-center gap-2">
                                    <span class="px-2 py-1 ${str.type === 'ascii' ? 'bg-blue-600' : 'bg-purple-600'} text-white rounded text-xs font-bold">
                                        ${str.type.toUpperCase()}
                                    </span>
                                    <span class="font-mono text-xs text-gray-400">0x${str.address.toString(16).toUpperCase()}</span>
                                </div>
                                <span class="text-xs text-gray-500">${str.length} chars</span>
                            </div>
                            <div class="text-sm text-gray-300 font-mono break-all">${escapeHtml(str.value)}</div>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;

        container.html(summaryHtml + controlsHtml + stringsHtml);
        setupStringHandlers(strings);
    }
    function setupStringHandlers(strings) {
        $('#strings-search').on('input', filterStrings);
        $('#strings-type-filter').on('change', filterStrings);
        $('#strings-min-length').on('change', filterStrings);
        $('#strings-reset').on('click', resetStringFilters);
        $('#strings-export').on('click', exportStrings);
    }
    function filterStrings() {
        const searchTerm = $('#strings-search').val().toLowerCase();
        const typeFilter = $('#strings-type-filter').val();
        const minLength = parseInt($('#strings-min-length').val()) || 0;

        const filteredStrings = stringsData.strings.filter(str => {
            const matchesSearch = !searchTerm || str.value.toLowerCase().includes(searchTerm);
            const matchesType = !typeFilter || str.type === typeFilter;
            const matchesLength = str.length >= minLength;
            
            return matchesSearch && matchesType && matchesLength;
        });

        renderFilteredStrings(filteredStrings);
        updateStringStats(filteredStrings);
    }
    function renderFilteredStrings(strings) {
        const container = $('#strings-table');
        container.empty();

        if (strings.length === 0) {
            container.html('<div class="text-center text-gray-500 py-4">No strings match the filters</div>');
            return;
        }

        container.html(strings.map((str, index) => `
            <div class="string-item p-3 bg-gray-800 rounded-lg border border-gray-700 hover:border-gray-600 transition cursor-pointer" 
                 data-string-index="${index}"
                 data-type="${str.type}"
                 data-length="${str.length}"
                 data-address="${str.address}">
                <div class="flex items-center justify-between mb-1">
                    <div class="flex items-center gap-2">
                        <span class="px-2 py-1 ${str.type === 'ascii' ? 'bg-blue-600' : 'bg-purple-600'} text-white rounded text-xs font-bold">
                            ${str.type.toUpperCase()}
                        </span>
                        <span class="font-mono text-xs text-gray-400">0x${str.address.toString(16).toUpperCase()}</span>
                    </div>
                    <span class="text-xs text-gray-500">${str.length} chars</span>
                </div>
                <div class="text-sm text-gray-300 font-mono break-all">${escapeHtml(str.value)}</div>
            </div>
        `).join(''));
    }
    function resetStringFilters() {
        $('#strings-search').val('');
        $('#strings-type-filter').val('');
        $('#strings-min-length').val('0');
        filterStrings();
    }
    function updateStringStats(filteredStrings) {
        const stats = `Showing ${filteredStrings.length} of ${stringsData.strings.length} strings`;
        $('#strings-stats').text(stats);
    }
    function exportStrings() {
        if (!stringsData) return;

        const content = stringsData.strings.map(str => 
            `0x${str.address.toString(16).toUpperCase()}\t${str.type}\t${str.value}`
        ).join('\n');

        const blob = new Blob([content], {type: 'text/plain'});
        const url = URL.createObjectURL(blob);
        
        const link = document.createElement('a');
        link.href = url;
        link.download = `strings-${currentJobId}.txt`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
    }
    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
    window.stringAnalysisManager = {
        initStringAnalysis: initStringAnalysis,
        renderStringAnalysis: renderStringAnalysis
    };
});
