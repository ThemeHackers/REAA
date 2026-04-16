$(document).ready(function() {
    let currentJobId = null;
    let memoryData = null;
    let hexViewerState = {
        currentSection: null,
        offset: 0,
        bytesPerLine: 16,
        searchPattern: null,
        virtualScroll: {
            visibleLines: 30,
            lineHeight: 20,
            scrollTop: 0,
            totalLines: 0
        }
    };
    
    function escapeHtml(unsafe) {
        if (typeof unsafe !== 'string') return unsafe;
        return unsafe
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }
    
    function sanitizeData(obj) {
        if (!obj || typeof obj !== 'object') return obj;
        
        if (Array.isArray(obj)) {
            return obj.map(item => sanitizeData(item));
        }
        
        const sanitized = {};
        for (const key in obj) {
            if (obj.hasOwnProperty(key)) {
                if (typeof obj[key] === 'string') {
                    sanitized[key] = escapeHtml(obj[key]);
                } else if (typeof obj[key] === 'object') {
                    sanitized[key] = sanitizeData(obj[key]);
                } else {
                    sanitized[key] = obj[key];
                }
            }
        }
        return sanitized;
    }
    
    function initMemoryLayout(jobId) {
        currentJobId = jobId;
        console.log('[Memory] Loading memory layout for job:', jobId);
        
        $('#memory-container').html('<div class="text-center text-gray-400 py-8"><div class="w-8 h-8 border-4 border-blue-600 border-t-transparent rounded-full animate-spin mx-auto mb-3"></div><p>Loading memory layout...</p></div>');
        
        fetchWithRetry(`/api/jobs/${jobId}/memory`, 3, 1000)
            .then(data => {
                console.log('[Memory] Memory data received:', data);
                
                if (!data || typeof data !== 'object') {
                    renderError('Invalid data format received');
                    return;
                }
                
                if (!data.sections || !Array.isArray(data.sections)) {
                    renderError('No sections found in data');
                    return;
                }
                
                if (data.sections.length === 0) {
                    renderError('No memory blocks available');
                    return;
                }
                
                memoryData = sanitizeData(data);
                renderMemoryLayout(memoryData);
            })
            .catch(error => {
                console.error('[Memory] Failed to load memory layout after retries:', error);
                renderError('Failed to load memory layout. Please try again.');
            });
    }
    
    function fetchWithRetry(url, maxRetries = 3, initialDelay = 1000) {
        return new Promise((resolve, reject) => {
            let retries = 0;
            let delay = initialDelay;
            
            function attemptFetch() {
                $.get(url)
                    .done(function(data) {
                        resolve(data);
                    })
                    .fail(function(xhr) {
                        retries++;
                        if (retries < maxRetries) {
                            console.log(`[Memory] Retry ${retries}/${maxRetries} in ${delay}ms`);
                            setTimeout(attemptFetch, delay);
                            delay *= 2; 
                        } else {
                            reject(xhr);
                        }
                    });
            }
            
            attemptFetch();
        });
    }
    
    let hexSearchWorker = null;
    function initHexSearchWorker() {
        if (hexSearchWorker) return;
        
        try {
            const workerBlob = new Blob([`
                ${document.querySelector('script[src*="hex-search-worker.js"]') ? 
                    '' : `
                self.onmessage = function(e) {
                    const { type, data } = e.data;
                    
                    if (type === 'search') {
                        performHexSearch(data);
                    }
                };
                
                function performHexSearch({ bytes, pattern, searchType }) {
                    const results = [];
                    const startTime = performance.now();
                    
                    if (!bytes || !pattern) {
                        self.postMessage({ type: 'searchResult', results: [], duration: 0 });
                        return;
                    }
                    
                    if (searchType === 'hex') {
                        const patternBytes = parseHexPattern(pattern);
                        if (patternBytes.length === 0) {
                            self.postMessage({ type: 'searchResult', results: [], duration: performance.now() - startTime });
                            return;
                        }
                        
                        for (let i = 0; i <= bytes.length - patternBytes.length; i++) {
                            let match = true;
                            for (let j = 0; j < patternBytes.length; j++) {
                                if (bytes[i + j] !== patternBytes[j]) {
                                    match = false;
                                    break;
                                }
                            }
                            if (match) {
                                results.push(i);
                            }
                        }
                    } else if (searchType === 'ascii') {
                        const patternBytes = pattern.split('').map(c => c.charCodeAt(0));
                        for (let i = 0; i <= bytes.length - patternBytes.length; i++) {
                            let match = true;
                            for (let j = 0; j < patternBytes.length; j++) {
                                if (bytes[i + j] !== patternBytes[j]) {
                                    match = false;
                                    break;
                                }
                            }
                            if (match) {
                                results.push(i);
                            }
                        }
                    }
                    
                    const duration = performance.now() - startTime;
                    self.postMessage({ type: 'searchResult', results, duration });
                }
                
                function parseHexPattern(pattern) {
                    const cleaned = pattern.replace(/\s+/g, '');
                    const bytes = [];
                    
                    for (let i = 0; i < cleaned.length; i += 2) {
                        if (i + 1 < cleaned.length) {
                            const byte = parseInt(cleaned.substr(i, 2), 16);
                            if (!isNaN(byte)) {
                                bytes.push(byte);
                            }
                        }
                    }
                    
                    return bytes;
                }
                `}
            `], { type: 'application/javascript' });
            
            hexSearchWorker = new Worker(URL.createObjectURL(workerBlob));
            
            hexSearchWorker.onmessage = function(e) {
                const { type, results, duration, message } = e.data;
                
                if (type === 'searchResult') {
                    if (hexViewerState.searchCallback) {
                        hexViewerState.searchCallback(results, duration);
                    }
                } else if (type === 'error') {
                    console.error('[Memory] Hex search worker error:', message);
                    showToast(message, 'error');
                }
            };
            
            console.log('[Memory] Hex search worker initialized');
        } catch (e) {
            console.error('[Memory] Failed to initialize hex search worker:', e);
        }
    }
    
    function performHexSearchWithWorker(pattern, searchType) {
        if (!hexSearchWorker) {
            initHexSearchWorker();
        }
        
        if (!hexSearchWorker) {

            performHexSearchMainThread(pattern, searchType);
            return;
        }
        
        $.get(`/api/jobs/${currentJobId}/memory/${hexViewerState.currentSection}/hex`, function(hexData) {
            const bytes = hexData.bytes || [];
            
            hexViewerState.searchCallback = function(results, duration) {
                console.log(`[Memory] Hex search completed in ${duration.toFixed(2)}ms, found ${results.length} matches`);
                
                hexViewerState.searchResults = results;
                hexViewerState.searchIndex = 0;
                
                if (results.length > 0) {
                    $('#hex-search-results').text(`Found ${results.length} matches (${duration.toFixed(2)}ms). Use Next/Prev to navigate.`);
                    hexViewerState.offset = results[0];
                    loadHexDump(hexViewerState.currentSection, results[0], pattern, results);
                } else {
                    $('#hex-search-results').text('No matches found');
                    loadHexDump(hexViewerState.currentSection, 0, null, []);
                }
            };
            
            hexSearchWorker.postMessage({
                type: 'search',
                data: { bytes, pattern, searchType }
            });
        }).fail(function() {
            showToast('Failed to load hex data for search', 'error');
        });
    }
    
    function performHexSearchMainThread(pattern, searchType) {
        console.log('[Memory] Using main thread for hex search (fallback)');
        
        $.get(`/api/jobs/${currentJobId}/memory/${hexViewerState.currentSection}/hex`, function(hexData) {
            const bytes = hexData.bytes || [];
            const results = [];
            const startTime = performance.now();
            
            if (searchType === 'hex') {
                const patternBytes = parseHexPattern(pattern);
                for (let i = 0; i <= bytes.length - patternBytes.length; i++) {
                    let match = true;
                    for (let j = 0; j < patternBytes.length; j++) {
                        if (bytes[i + j] !== patternBytes[j]) {
                            match = false;
                            break;
                        }
                    }
                    if (match) {
                        results.push(i);
                    }
                }
            } else if (searchType === 'ascii') {
                const patternBytes = pattern.split('').map(c => c.charCodeAt(0));
                for (let i = 0; i <= bytes.length - patternBytes.length; i++) {
                    let match = true;
                    for (let j = 0; j < patternBytes.length; j++) {
                        if (bytes[i + j] !== patternBytes[j]) {
                            match = false;
                            break;
                        }
                    }
                    if (match) {
                        results.push(i);
                    }
                }
            }
            
            const duration = performance.now() - startTime;
            console.log(`[Memory] Hex search completed in ${duration.toFixed(2)}ms (main thread), found ${results.length} matches`);
            
            hexViewerState.searchResults = results;
            hexViewerState.searchIndex = 0;
            
            if (results.length > 0) {
                $('#hex-search-results').text(`Found ${results.length} matches (${duration.toFixed(2)}ms). Use Next/Prev to navigate.`);
                hexViewerState.offset = results[0];
                loadHexDump(hexViewerState.currentSection, results[0], pattern, results);
            } else {
                $('#hex-search-results').text('No matches found');
            }
        });
    }
    
    function parseHexPattern(pattern) {
        const cleaned = pattern.replace(/\s+/g, '').toUpperCase();
        const bytes = [];
        
        if (cleaned.length === 0) return bytes;
        
        for (let i = 0; i < cleaned.length; i += 2) {
            const hexPair = cleaned.substr(i, 2);
            
            if (hexPair.length === 1) {
                const byte = parseInt(hexPair, 16);
                if (!isNaN(byte)) {
                    bytes.push(byte);
                }
            } else {
                if (!/^[0-9A-F]{2}$/.test(hexPair)) {
                    console.warn(`Invalid hex pattern: ${hexPair} at position ${i}`);
                    continue;
                }
                const byte = parseInt(hexPair, 16);
                if (!isNaN(byte)) {
                    bytes.push(byte);
                }
            }
        }
        
        return bytes;
    }
    
    function renderError(message) {
        $('#memory-container').html(`
            <div class="text-center text-red-400 py-8">
                <div class="text-4xl mb-3">⚠️</div>
                <p class="text-lg mb-2">${message}</p>
                <p class="text-sm text-gray-500">Please try refreshing the page or check the job data</p>
            </div>
        `);
    }
    
    function renderMemoryLayout(data) {
        console.time('[Memory] renderMemoryLayout');
        const container = $('#memory-container');
        container.empty();

        const validSections = data.sections.filter(section => {
            if (!section) return false;
            if (typeof section.size !== 'number' || section.size < 0) return false;
            if (!section.address && section.address !== 0) return false;
            return true;
        });
        
        if (validSections.length === 0) {
            renderError('No valid memory blocks found');
            console.timeEnd('[Memory] renderMemoryLayout');
            return;
        }
        
        const totalSize = data.total_size || validSections.reduce((sum, s) => sum + s.size, 0);
        const baseAddress = data.base_address || (validSections.length > 0 ? validSections[0].address : 0);
        
        const summaryHtml = `
            <div class="memory-summary mb-6 p-6 bg-gray-800 rounded-lg border border-gray-700">
                <h4 class="text-sm font-semibold text-gray-300 mb-4">Memory Summary</h4>
                <div class="grid grid-cols-2 md:grid-cols-3 gap-6">
                    <div class="text-center p-4">
                        <div class="text-2xl font-bold text-green-400">${formatSize(totalSize)}</div>
                        <div class="text-xs text-gray-400">Total Size</div>
                    </div>
                    <div class="text-center p-4">
                        <div class="text-2xl font-bold text-blue-400">${data.sections.length}</div>
                        <div class="text-xs text-gray-400">Memory Blocks</div>
                    </div>
                    <div class="text-center p-4">
                        <div class="text-2xl font-bold text-purple-400">0x${baseAddress.toString(16).toUpperCase()}</div>
                        <div class="text-xs text-gray-400">Base Address</div>
                    </div>
                </div>
            </div>
        `;
        
        const sectionsHtml = `
            <div class="memory-sections mb-6">
                <h4 class="text-sm font-semibold text-gray-300 mb-3">Memory Blocks</h4>
                <div class="bg-gray-800 rounded-lg border border-gray-700 overflow-hidden">
                    <table class="w-full text-xs">
                        <thead class="bg-gray-700">
                            <tr>
                                <th class="px-4 py-2 text-left text-gray-300">Block Name</th>
                                <th class="px-4 py-2 text-left text-gray-300">Start Address</th>
                                <th class="px-4 py-2 text-left text-gray-300">End Address</th>
                                <th class="px-4 py-2 text-right text-gray-300">Size</th>
                                <th class="px-4 py-2 text-center text-gray-300">Type</th>
                                <th class="px-4 py-2 text-center text-gray-300">Permissions</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-gray-700">
                            ${data.sections.map((section, index) => {
                                const percentage = ((section.size / totalSize) * 100).toFixed(2);
                                const startAddr = section.start || '0x' + section.address.toString(16);
                                const endAddr = section.end || '0x' + (section.address + section.size).toString(16);
                                
                            
                                let permBadges = '';
                                if (typeof section.permissions === 'string') {
                                    if (section.permissions.includes('R') || section.permissions.includes('r')) {
                                        permBadges += '<span class="px-2 py-1 bg-green-600 text-white rounded text-xs font-bold">R</span> ';
                                    }
                                    if (section.permissions.includes('W') || section.permissions.includes('w')) {
                                        permBadges += '<span class="px-2 py-1 bg-red-600 text-white rounded text-xs font-bold">W</span> ';
                                    }
                                    if (section.permissions.includes('X') || section.permissions.includes('x')) {
                                        permBadges += '<span class="px-2 py-1 bg-blue-600 text-white rounded text-xs font-bold">X</span> ';
                                    }
                                } else {
                                    const perms = section.permissions || { read: false, write: false, execute: false };
                                    if (perms.read || perms.read === true) {
                                        permBadges += '<span class="px-2 py-1 bg-green-600 text-white rounded text-xs font-bold">R</span> ';
                                    }
                                    if (perms.write || perms.write === true) {
                                        permBadges += '<span class="px-2 py-1 bg-red-600 text-white rounded text-xs font-bold">W</span> ';
                                    }
                                    if (perms.execute || perms.execute === true) {
                                        permBadges += '<span class="px-2 py-1 bg-blue-600 text-white rounded text-xs font-bold">X</span> ';
                                    }
                                }
                                
                                return `
                                    <tr class="hover:bg-gray-700/50 cursor-pointer memory-section-row" data-section="${section.name}">
                                        <td class="px-4 py-3 text-gray-300 font-mono">${escapeHtml(section.name)}</td>
                                        <td class="px-4 py-3 text-gray-300 font-mono">${escapeHtml(startAddr)}</td>
                                        <td class="px-4 py-3 text-gray-300 font-mono">${escapeHtml(endAddr)}</td>
                                        <td class="px-4 py-3 text-right text-gray-300">${formatSize(section.size)} (${percentage}%)</td>
                                        <td class="px-4 py-3 text-center text-gray-300 capitalize">${escapeHtml((section.type && section.type !== 'unknown') ? section.type : guessSectionTypeFromData(section))}</td>
                                        <td class="px-4 py-3 text-center">${permBadges || '<span class="text-gray-500">---</span>'}</td>
                                    </tr>
                                `;
                            }).join('')}
                        </tbody>
                    </table>
                </div>
            </div>
        `;
        
        const visualMapHtml = `
            <div class="memory-visual-map mb-6 p-4 bg-gray-800 rounded-lg border border-gray-700">
                <h4 class="text-sm font-semibold text-gray-300 mb-3">Memory Layout Visualization</h4>
                <div class="relative h-8 bg-gray-900 rounded overflow-hidden">
                    ${validSections.map((section, index) => {
                        const offset = baseAddress ? ((section.address - baseAddress) / totalSize) * 100 : 0;
                        const width = Math.max(0.5, (section.size / totalSize) * 100);
                        const colorClass = index % 2 === 0 ? 'bg-blue-600' : 'bg-green-600';
                        
                        return `
                            <div class="absolute ${colorClass} hover:opacity-80 transition cursor-pointer border-r border-gray-900"
                                 style="left: ${offset}%; width: ${width}%; height: 100%;"
                                 title="${section.name}: ${formatSize(section.size)} @ ${section.start}"
                                 data-section="${section.name}">
                            </div>
                        `;
                    }).join('')}
                </div>
                <div class="flex justify-between text-xs text-gray-500 mt-2 font-mono">
                    <span>0x${baseAddress.toString(16).toUpperCase()}</span>
                    <span>0x${(baseAddress + totalSize).toString(16).toUpperCase()}</span>
                </div>
            </div>
        `;
        
        const hexViewerHtml = `
            <div class="hex-viewer mt-6 p-4 bg-gray-800 rounded-lg border border-gray-700">
                <div class="flex items-center justify-between mb-3">
                    <h4 class="text-sm font-semibold text-gray-300">Hex Dump Viewer</h4>
                    <div class="flex gap-2">
                        <button id="hex-search-btn" class="px-3 py-1 bg-blue-600 hover:bg-blue-700 text-white rounded text-xs">Search</button>
                        <button id="hex-export" class="px-3 py-1 bg-green-600 hover:bg-green-700 text-white rounded text-xs">Export</button>
                    </div>
                </div>
                
                <!-- Search Panel -->
                <div id="hex-search-panel" class="hidden mb-3 p-3 bg-gray-900 rounded border border-gray-700">
                    <div class="flex gap-2 mb-2">
                        <select id="hex-search-type" class="px-2 py-1 bg-gray-800 text-gray-300 rounded text-xs border border-gray-600">
                            <option value="hex">Hex</option>
                            <option value="ascii">ASCII</option>
                        </select>
                        <input type="text" id="hex-search-input" placeholder="Search pattern..." class="flex-1 px-2 py-1 bg-gray-800 text-gray-300 rounded text-xs border border-gray-600 focus:outline-none focus:border-blue-500">
                        <button id="hex-search-execute" class="px-3 py-1 bg-blue-600 hover:bg-blue-700 text-white rounded text-xs">Go</button>
                        <button id="hex-search-close" class="px-2 py-1 bg-gray-700 hover:bg-gray-600 text-gray-300 rounded text-xs">×</button>
                    </div>
                    <div id="hex-search-results" class="text-xs text-gray-400"></div>
                    <div class="flex gap-2 mt-2">
                        <button id="hex-search-prev" class="px-2 py-1 bg-gray-700 hover:bg-gray-600 text-gray-300 rounded text-xs">← Prev</button>
                        <button id="hex-search-next" class="px-2 py-1 bg-gray-700 hover:bg-gray-600 text-gray-300 rounded text-xs">Next →</button>
                    </div>
                </div>
                
                <div id="hex-content" class="bg-gray-900 rounded p-3 font-mono text-xs text-gray-300 overflow-x-auto max-h-[600px] overflow-y-auto">
                    <div class="text-gray-500 text-center py-4">Select a section to view hex dump</div>
                </div>
            </div>
        `;

        container.html(`
            ${summaryHtml}
            ${visualMapHtml}
            ${sectionsHtml}
            ${hexViewerHtml}
        `);
        
        console.timeEnd('[Memory] renderMemoryLayout');
        updateSidebarStatistics(data);
        
        $('.memory-section-row').on('click', function() {
            const sectionName = $(this).data('section');
            console.log('[Memory] Clicked section:', sectionName);
            
            try {
                showSectionDetailsInSidebar(sectionName);
                loadHexDump(sectionName, 0, null, null);
            } catch (error) {
                console.error('[Memory] Error in click handler:', error);
            }
        });
        
        $('#ml-search').on('input', function() {
            const searchTerm = $(this).val().toLowerCase();
            filterSections(searchTerm);
        });
        
        $('#hex-export').on('click', function() {
            if (hexViewerState.currentSection) {
                exportHexDump(hexViewerState.currentSection);
            } else {
                showToast('Please select a section first', 'warning');
            }
        });
        
        $('#hex-search-btn').on('click', function() {
            $('#hex-search-panel').toggleClass('hidden');
        });
        
        $('#hex-search-close').on('click', function() {
            $('#hex-search-panel').addClass('hidden');
        });
        
       
        $('#hex-search-execute').on('click', function() {
            const pattern = $('#hex-search-input').val();
            const searchType = $('#hex-search-type').val();
            
            if (!pattern) {
                showToast('Please enter a search pattern', 'warning');
                return;
            }
            
            if (!hexViewerState.currentSection) {
                showToast('Please select a section first', 'warning');
                return;
            }
            
            hexViewerState.searchPattern = pattern;
            $('#hex-search-results').text('Searching...');
            
            if (!hexSearchWorker) {
                initHexSearchWorker();
            }
            
            if (hexSearchWorker) {
                performHexSearchWithWorker(pattern, searchType);
            } else {
                performHexSearchMainThread(pattern, searchType);
            }
        });
        
        $('#hex-search-prev').on('click', function() {
            if (hexViewerState.searchResults && hexViewerState.searchResults.length > 0) {
                hexViewerState.searchIndex--;
                if (hexViewerState.searchIndex < 0) {
                    hexViewerState.searchIndex = hexViewerState.searchResults.length - 1;
                }
                hexViewerState.offset = hexViewerState.searchResults[hexViewerState.searchIndex];
                loadHexDump(hexViewerState.currentSection, hexViewerState.offset, hexViewerState.searchPattern, hexViewerState.searchResults);
                $('#hex-search-results').text(`Match ${hexViewerState.searchIndex + 1} of ${hexViewerState.searchResults.length}`);
            }
        });
        
        $('#hex-search-next').on('click', function() {
            if (hexViewerState.searchResults && hexViewerState.searchResults.length > 0) {
                hexViewerState.searchIndex++;
                if (hexViewerState.searchIndex >= hexViewerState.searchResults.length) {
                    hexViewerState.searchIndex = 0;
                }
                hexViewerState.offset = hexViewerState.searchResults[hexViewerState.searchIndex];
                loadHexDump(hexViewerState.currentSection, hexViewerState.offset, hexViewerState.searchPattern, hexViewerState.searchResults);
                $('#hex-search-results').text(`Match ${hexViewerState.searchIndex + 1} of ${hexViewerState.searchResults.length}`);
            }
        });
    }
    
    function loadHexDump(sectionName, offset = 0, searchPattern = null, searchResults = null) {
        console.log('[Memory] === loadHexDump START ===');
        console.log('[Memory] loadHexDump called for:', sectionName, 'offset:', offset, 'searchPattern:', searchPattern, 'searchResults:', searchResults);
        
        const section = memoryData.sections.find(s => s.name === sectionName);
        if (!section) {
            console.error('[Memory] Section not found:', sectionName);
            return;
        }
        
        console.log('[Memory] Found section:', section);
        hexViewerState.currentSection = sectionName;
        hexViewerState.offset = offset;
        
        const hexContent = $('#hex-content');
        console.log('[Memory] hex-content element found:', hexContent.length);
        
        
        hexContent.html('<div class="text-gray-400 text-center py-4"><div class="w-6 h-6 border-2 border-blue-600 border-t-transparent rounded-full animate-spin mx-auto mb-2"></div><p>Loading hex dump...</p></div>');
        
        
        $.get(`/api/jobs/${currentJobId}/memory/${sectionName}/hex`, function(hexData) {
            console.log('[Memory] Hex data received:', hexData);
            
            if (hexData && hexData.bytes && hexData.bytes.length > 0) {
                renderHexBytes(hexData.bytes, section, false, offset, searchPattern, hexViewerState.searchResults);
            } else {
                const errorMsg = hexData && hexData.error ? hexData.error : 'No hex data available from Ghidra API';
                $('#hex-content').html(`
                    <div class="text-red-400 text-center py-4">
                        <div class="text-4xl mb-3">⚠️</div>
                        <p class="text-lg mb-2">${errorMsg}</p>
                        <p class="text-sm text-gray-500">Hex data not available for this section</p>
                    </div>
                `);
            }
        }).fail(function(xhr) {
            console.error('[Memory] Failed to fetch hex data:', xhr);
            $('#hex-content').html(`
                <div class="text-red-400 text-center py-4">
                    <div class="text-4xl mb-3">❌</div>
                    <p class="text-lg mb-2">Failed to load hex data</p>
                    <p class="text-sm text-gray-500">API request failed</p>
                </div>
            `);
        });
    }
    
    function renderHexBytes(bytes, section, isDummy = false, offset = 0, searchPattern = null, searchResults = null) {
        const hexContent = $('#hex-content');
        const bytesPerLine = 16;
        
        const displayBytes = bytes.slice(offset, offset + 4096); 
        const startAddress = section.address + offset;
        
        if (searchResults) {
            hexViewerState.searchResults = searchResults;
        }
        
        let searchBytes = [];
        if (searchPattern) {
            searchBytes = parseHexPattern(searchPattern);
        }
        
        let html = `
            <div class="text-gray-400 mb-2">
                <span class="text-blue-400">${escapeHtml(section.name)}</span> @ 0x${section.address.toString(16).toUpperCase()} - 0x${(section.address + section.size).toString(16).toUpperCase()}
            </div>
            ${searchPattern ? `<div class="text-yellow-400 text-xs mb-2">🔍 Searching for: ${escapeHtml(searchPattern)}</div>` : ''}
            <div class="text-gray-500 text-xs mb-2">Showing: ${formatSize(displayBytes.length)} starting at offset 0x${offset.toString(16).toUpperCase()}</div>
            <div class="text-gray-500 text-xs mb-2">Total: ${Math.ceil(bytes.length / bytesPerLine)} lines (${formatSize(bytes.length)})</div>
            <div class="bg-gray-900 rounded border border-gray-700 p-3 font-mono text-xs overflow-x-auto max-h-[600px] overflow-y-auto">
        `;
        
        for (let i = 0; i < displayBytes.length; i += bytesPerLine) {
            const lineBytes = displayBytes.slice(i, i + bytesPerLine);
            const lineOffset = startAddress + i;
            
            const offsetHex = lineOffset.toString(16).padStart(8, '0').toUpperCase();
            
            let hexPart = '';
            let asciiPart = '';
            
            for (let j = 0; j < lineBytes.length; j++) {
                const byte = lineBytes[j];
                const globalIndex = offset + i + j;
                const hexByte = byte.toString(16).padStart(2, '0');
                const asciiChar = (byte >= 32 && byte <= 126) ? String.fromCharCode(byte) : '.';
                
                const isMatch = hexViewerState.searchResults && 
                               hexViewerState.searchResults.some(resultPos => {
                                   const patternLength = searchBytes.length;
                                   return globalIndex >= resultPos && 
                                          globalIndex < resultPos + patternLength;
                               });
                
                const highlightClass = isMatch ? 'bg-yellow-500 text-black' : 'text-gray-300';
                
                hexPart += `<span class="${highlightClass}">${hexByte}</span> `;
                asciiPart += `<span class="${isMatch ? 'bg-yellow-500 text-black' : 'text-gray-400'}">${asciiChar}</span>`;
            }
            
            html += `
                <div class="flex">
                    <span class="w-24 text-gray-400">${offsetHex}</span>
                    <span class="w-48">${hexPart}</span>
                    <span>${asciiPart}</span>
                </div>
            `;
        }
        
        if (bytes.length > displayBytes.length) {
            html += `<div class="text-gray-500 text-center mt-2">... showing ${formatSize(displayBytes.length)} of ${formatSize(bytes.length)}</div>`;
        }
        
        html += '</div>';
        
        hexContent.html(html);
        console.log('[Memory] Hex bytes rendered successfully');
    }
    
    function initVirtualHexDump(section) {
        const container = $('#hex-content');
        const totalBytes = section.size;
        const totalLines = Math.ceil(totalBytes / hexViewerState.bytesPerLine);
        
        hexViewerState.virtualScroll.totalLines = totalLines;
        

        const scrollContainer = $(`
            <div class="hex-virtual-scroll mt-3 border border-gray-700 rounded bg-gray-900" 
                 style="height: 320px; overflow-y: auto; position: relative;">
                <div class="hex-spacer" style="height: ${totalLines * hexViewerState.virtualScroll.lineHeight}px;"></div>
                <div class="hex-viewport" style="position: absolute; top: 0; left: 0; right: 0;"></div>
            </div>
        `);
        
        container.append(scrollContainer);
        
     
        scrollContainer.on('scroll', function() {
            const scrollTop = $(this).scrollTop();
            hexViewerState.virtualScroll.scrollTop = scrollTop;
            renderVisibleHexLines(scrollTop, totalLines);
        });
        
      
        renderVisibleHexLines(0, totalLines);
    }
    
    function renderVisibleHexLines(scrollTop, totalLines) {
        const viewport = $('.hex-viewport');
        if (!viewport.length) return;
        
        const visibleLines = hexViewerState.virtualScroll.visibleLines;
        const lineHeight = hexViewerState.virtualScroll.lineHeight;
        const bytesPerLine = hexViewerState.bytesPerLine;
        
        const startLine = Math.floor(scrollTop / lineHeight);
        const endLine = Math.min(startLine + visibleLines, totalLines);
        
        const startOffset = startLine * bytesPerLine;
        const endOffset = endLine * bytesPerLine;
        
       
        $.get(`/api/jobs/${currentJobId}/memory/${hexViewerState.currentSection}/hex`, function(hexData) {
            const bytes = hexData.bytes || [];
            const displayBytes = bytes.slice(startOffset, endOffset);
            
            let html = '';
            for (let i = 0; i < displayBytes.length; i += bytesPerLine) {
                const lineBytes = displayBytes.slice(i, i + bytesPerLine);
                const offset = startOffset + i;
                
                const hexPart = lineBytes.map(b => b.toString(16).padStart(2, '0')).join(' ');
                const asciiPart = lineBytes.map(b => (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.').join('');
                
                html += `
                    <div class="flex text-xs font-mono" style="height: ${lineHeight}px; line-height: ${lineHeight}px;">
                        <span class="w-24 text-gray-400">${offset.toString(16).padStart(8, '0').toUpperCase()}</span>
                        <span class="w-48 text-gray-300">${hexPart}</span>
                        <span class="text-gray-400">${asciiPart}</span>
                    </div>
                `;
            }
            
            viewport.css('top', `${startLine * lineHeight}px`);
            viewport.html(html);
        }).fail(function() {
            viewport.html('<div class="text-red-400 text-center py-4">Failed to load hex data</div>');
        });
    }
    
    function exportHexDump(sectionName) {
        const section = memoryData.sections.find(s => s.name === sectionName);
        if (!section) return;
        
        showToast('Exporting hex data...', 'info');
        
        $.get(`/api/jobs/${currentJobId}/memory/${sectionName}/hex`, function(hexData) {
            if (hexData && hexData.bytes && hexData.bytes.length > 0) {
                const exportData = {
                    section: section.name,
                    address: '0x' + section.address.toString(16).toUpperCase(),
                    endAddress: '0x' + (section.address + section.size).toString(16).toUpperCase(),
                    size: section.size,
                    type: section.type || guessSectionTypeFromData(section),
                    permissions: section.permissions,
                    sectionType: hexData.section_type,
                    hexData: Array.from(hexData.bytes),
                    totalLines: Math.ceil(hexData.bytes.length / 16),
                    timestamp: new Date().toISOString()
                };
                
                const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `memory_${section.name}.json`;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
                
                showToast(`Exported ${section.name} (${formatSize(hexData.bytes.length)})`, 'success');
            } else {
                showToast('No hex data available to export', 'error');
            }
        }).fail(function() {
            showToast('Failed to load hex data for export', 'error');
        });
    }
    
    function showToast(message, type = 'info') {
        const colors = {
            success: 'bg-green-600',
            error: 'bg-red-600',
            warning: 'bg-yellow-600',
            info: 'bg-blue-600'
        };
        
        const toast = $(`
            <div class="fixed bottom-4 right-4 ${colors[type]} text-white px-4 py-2 rounded-lg shadow-lg z-50 text-sm">
                ${message}
            </div>
        `);
        
        $('body').append(toast);
        setTimeout(() => toast.remove(), 3000);
    }
    
    function updateSidebarStatistics(data) {
       
        const validSections = data.sections.filter(section => {
            if (!section) return false;
            if (typeof section.size !== 'number' || section.size < 0) return false;
            if (!section.address && section.address !== 0) return false;
            return true;
        });
        
        const totalSize = data.total_size || validSections.reduce((sum, s) => sum + s.size, 0);
        $('#ml-total-size').text(formatSize(totalSize));
        $('#ml-sections').text(validSections.length);
        
        const codeSize = validSections.filter(s => getSectionType(s.name) === 'code').reduce((sum, s) => sum + s.size, 0);
        const dataSize = validSections.filter(s => getSectionType(s.name) === 'data').reduce((sum, s) => sum + s.size, 0);
        
        $('#ml-code-size').text(formatSize(codeSize));
        $('#ml-data-size').text(formatSize(dataSize));
    }
    
    function showSectionDetailsInSidebar(sectionName) {
        const section = memoryData.sections.find(s => s.name === sectionName);
        if (!section) return;

        const startAddr = section.start || '0x' + section.address.toString(16);
        const endAddr = section.end || '0x' + (section.address + section.size).toString(16);
        const sectionType = (section.type && section.type !== 'unknown') ? section.type : guessSectionTypeFromData(section);
        
       
        let permBadges = '';
        if (typeof section.permissions === 'string') {
            if (section.permissions.includes('R') || section.permissions.includes('r')) {
                permBadges += '<span class="px-2 py-1 bg-green-600 text-white rounded text-xs">R</span> ';
            } else {
                permBadges += '<span class="px-2 py-1 bg-gray-600 text-gray-400 rounded text-xs">-</span> ';
            }
            if (section.permissions.includes('W') || section.permissions.includes('w')) {
                permBadges += '<span class="px-2 py-1 bg-red-600 text-white rounded text-xs">W</span> ';
            } else {
                permBadges += '<span class="px-2 py-1 bg-gray-600 text-gray-400 rounded text-xs">-</span> ';
            }
            if (section.permissions.includes('X') || section.permissions.includes('x')) {
                permBadges += '<span class="px-2 py-1 bg-blue-600 text-white rounded text-xs">X</span> ';
            } else {
                permBadges += '<span class="px-2 py-1 bg-gray-600 text-gray-400 rounded text-xs">-</span> ';
            }
        } else {
            const perms = section.permissions || { read: false, write: false, execute: false };
            if (perms.read || perms.read === true) {
                permBadges += '<span class="px-2 py-1 bg-green-600 text-white rounded text-xs">R</span> ';
            } else {
                permBadges += '<span class="px-2 py-1 bg-gray-600 text-gray-400 rounded text-xs">-</span> ';
            }
            if (perms.write || perms.write === true) {
                permBadges += '<span class="px-2 py-1 bg-red-600 text-white rounded text-xs">W</span> ';
            } else {
                permBadges += '<span class="px-2 py-1 bg-gray-600 text-gray-400 rounded text-xs">-</span> ';
            }
            if (perms.execute || perms.execute === true) {
                permBadges += '<span class="px-2 py-1 bg-blue-600 text-white rounded text-xs">X</span> ';
            } else {
                permBadges += '<span class="px-2 py-1 bg-gray-600 text-gray-400 rounded text-xs">-</span> ';
            }
        }

        const detailsHtml = `
            <div class="space-y-3">
                <div>
                    <div class="text-xs text-gray-500">Block Name</div>
                    <div class="text-sm text-gray-300 font-mono">${escapeHtml(section.name)}</div>
                </div>
                <div>
                    <div class="text-xs text-gray-500">Start Address</div>
                    <div class="font-mono text-sm text-gray-300">${escapeHtml(startAddr)}</div>
                </div>
                <div>
                    <div class="text-xs text-gray-500">End Address</div>
                    <div class="font-mono text-sm text-gray-300">${escapeHtml(endAddr)}</div>
                </div>
                <div>
                    <div class="text-xs text-gray-500">Size</div>
                    <div class="text-sm text-gray-300">${formatSize(section.size)}</div>
                </div>
                <div>
                    <div class="text-xs text-gray-500">Type</div>
                    <div class="text-sm text-gray-300 capitalize">${escapeHtml(sectionType)}</div>
                </div>
                <div>
                    <div class="text-xs text-gray-500">Permissions</div>
                    <div class="text-sm text-gray-300">
                        <span class="inline-flex gap-1">
                            ${permBadges}
                        </span>
                    </div>
                </div>
            </div>
        `;
        $('#ml-section-details').html(detailsHtml);
    }
    
    function filterSections(searchTerm) {
        if (!searchTerm) {
            $('.memory-section-row').show();
            return;
        }
        
        $('.memory-section-row').each(function() {
            const sectionName = $(this).data('section').toLowerCase();
            if (sectionName.includes(searchTerm)) {
                $(this).show();
            } else {
                $(this).hide();
            }
        });
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
    
    function guessSectionTypeFromData(section) {
        if (!section) return 'unknown';
        
        const address = section.address || 0;
        const size = section.size || 0;
        const name = section.name || '';
        const lowerName = name.toLowerCase();
        const perms = section.permissions || '';
        
       
        if (lowerName.includes('.text') || lowerName.includes('code') || lowerName.includes('_text')) return 'code';
        if (lowerName.includes('.data') || lowerName.includes('_data') || lowerName.includes('.rdata')) return 'data';
        if (lowerName.includes('.bss') || lowerName.includes('_bss')) return 'bss';
        if (lowerName.includes('.rodata') || lowerName.includes('.rdata') || lowerName.includes('rodata')) return 'rodata';
        if (lowerName.includes('.idata') || lowerName.includes('.import') || lowerName.includes('idata')) return 'import';
        if (lowerName.includes('.edata') || lowerName.includes('.export') || lowerName.includes('edata')) return 'export';
        if (lowerName.includes('.reloc') || lowerName.includes('reloc')) return 'reloc';
        if (lowerName.includes('.rsrc') || lowerName.includes('resource') || lowerName.includes('rsrc')) return 'resource';
        if (lowerName.includes('.tls') || lowerName.includes('tls')) return 'tls';
        if (lowerName.includes('stack') || lowerName.includes('_stack')) return 'stack';
        if (lowerName.includes('heap') || lowerName.includes('_heap')) return 'heap';
        if (lowerName.includes('.symtab') || lowerName.includes('symbol')) return 'symbol';
        if (lowerName.includes('.strtab') || lowerName.includes('string')) return 'string';
        if (lowerName.includes('.dynsym') || lowerName.includes('dynamic')) return 'dynamic';
        if (lowerName.includes('.got') || lowerName.includes('plt')) return 'got';
        if (lowerName.includes('.init') || lowerName.includes('.fini')) return 'init';
        

        if (address >= 0x400000 && address < 0x410000 && size < 65536) {
            if (perms.includes('X') || perms.includes('x')) return 'code';
            return 'data';
        }
        
       
        if (address >= 0x400000 && address < 0x500000) {
            if (perms.includes('X') || perms.includes('x')) return 'code';
            if (size < 500000) return 'code';
            return 'data';
        }
        
       
        if (address >= 0x500000 && address < 0x600000) {
            return 'data';
        }
        

        if (address >= 0x600000 && address < 0x700000) {
            return 'resource';
        }
       
        if (address >= 0x140000000 && address < 0x140010000) {
            return 'code';
        }
        if (address >= 0x140010000 && address < 0x140020000) {
            return 'data';
        }
        
        if (address >= 0x10000000 && address < 0x11000000) {
            if (perms.includes('X') || perms.includes('x')) return 'code';
            return 'data';
        }
        
     
        if (size > 10485760) {
            return 'data';
        }
        
        
        if (size > 1048576 && size < 10485760) {
            if (address < 0x500000) return 'code';
            if (address >= 0x140000000 && address < 0x140010000) return 'code';
            return 'data';
        }
        
      
        if (size < 65536) {
            if (address >= 0x400000 && address < 0x410000) return 'code';
            if (address >= 0x500000 && address < 0x510000) return 'data';
            if (address >= 0xfb000000) return 'data';
            if (address >= 0x7ffe0000 && address <= 0x7fffffff) return 'stack';
            return 'unknown';
        }
        
       
        if (address >= 0x08048000 && address < 0x08050000) {
            return 'code';
        }
        if (address >= 0x08050000 && address < 0x08060000) {
            return 'data';
        }
        
       
        if (address >= 0x5600000000 && address < 0x5600100000) {
            return 'code';
        }
        if (address >= 0x5600100000 && address < 0x5600200000) {
            return 'data';
        }
        
      
        if (address >= 0x08000000 && address < 0x09000000) {
            if (perms.includes('X') || perms.includes('x')) return 'code';
            return 'data';
        }
        
       
        if (address >= 0x7f0000000000 && address < 0x7f0100000000) {
            if (perms.includes('X') || perms.includes('x')) return 'code';
            return 'data';
        }
        
      
        if (address >= 0xc0000000 || address >= 0xffffffff80000000) {
            return 'data';
        }
        
      
        if (address >= 0xffff800000000000) {
            return 'data';
        }
        
      
        if (lowerName.includes('block')) {
            if (address < 0x500000) return 'code';
            if (address >= 0xfb000000) return 'data';
            if (address >= 0x140000000 && address < 0x140010000) return 'code';
            return 'data';
        }
        
     
        if (perms.includes('X') || perms.includes('x')) {
            return 'code';
        }
        if (perms.includes('W') || perms.includes('w')) {
            return 'data';
        }
        if (perms.includes('R') || perms.includes('r')) {
            if (address < 0x500000) return 'code';
            if (address >= 0x140000000 && address < 0x140010000) return 'code';
            return 'data';
        }
        

        if (address < 0x100000) return 'code';
        if (address >= 0x100000 && address < 0x500000) return 'code';
        if (address >= 0x500000 && address < 0x700000) return 'data';
        
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
        if (bytes === 0 || bytes === null || bytes === undefined || isNaN(bytes)) return '0 B';
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
                const patternBytes = pattern.split(/\s+/).map(b => {
                    const parsed = parseInt(b, 16);
                    return isNaN(parsed) ? null : parsed;
                }).filter(b => b !== null);
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
                let regex;
                try {
                    regex = new RegExp(pattern, 'g');
                } catch (e) {
                    $('#hex-search-results').text('Invalid regex pattern');
                    return;
                }
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
