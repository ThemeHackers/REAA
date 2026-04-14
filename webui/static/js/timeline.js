$(document).ready(function() {
    let currentJobId = null;
    let timelineData = null;
    let svg = null;
    let zoom = null;
    let originalEvents = [];
    function initTimeline(jobId) {
        currentJobId = jobId;
        $.get(`/api/timeline/${jobId}`, function(data) {
            timelineData = data;
            originalEvents = JSON.parse(JSON.stringify(data.events || []));
            renderTimeline(data);
        }).fail(function(xhr) {
            console.error('Failed to load timeline:', xhr);
            $('#timeline-container').html('<div class="text-center text-gray-500 py-8">Failed to load timeline data</div>');
        });
        setupWebSocketListeners();
    }
    function setupWebSocketListeners() {
        if (window.wsManager) {
            window.wsManager.on('analysis_progress', (data) => {
                addTimelineEvent(data);
            });
        }
    }
    function renderTimeline(data) {
        const container = $('#timeline-container');
        container.empty();

        if (!data || !data.events || data.events.length === 0) {
            container.html('<div class="text-center text-gray-500 py-8">No timeline data available</div>');
            return;
        }
        const processedData = processTimelineData(data);
        const events = processedData.events;
        const controlsHtml = `
            <div class="timeline-controls mb-4 p-4 bg-gray-800 rounded-lg border border-gray-700">
                <div class="flex flex-wrap gap-4 items-center">
                    <div class="flex-1 min-w-[200px]">
                        <input type="text" id="timeline-search" placeholder="Search events..." 
                               class="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-gray-200 text-sm focus:outline-none focus:border-blue-500">
                    </div>
                    <div>
                        <select id="timeline-category-filter" class="px-3 py-2 bg-gray-700 border border-gray-600 rounded text-gray-200 text-sm focus:outline-none focus:border-blue-500">
                            <option value="">All Categories</option>
                            <option value="analysis">Analysis</option>
                            <option value="security">Security</option>
                            <option value="decompilation">Decompilation</option>
                            <option value="report">Report</option>
                        </select>
                    </div>
                    <div>
                        <select id="timeline-status-filter" class="px-3 py-2 bg-gray-700 border border-gray-600 rounded text-gray-200 text-sm focus:outline-none focus:border-blue-500">
                            <option value="">All Status</option>
                            <option value="completed">Completed</option>
                            <option value="in_progress">In Progress</option>
                        <option value="pending">Pending</option>
                        <option value="failed">Failed</option>
                    </select>
                    </div>
                    <div class="flex gap-2">
                        <button id="timeline-reset" class="px-3 py-2 bg-gray-700 hover:bg-gray-600 text-gray-200 rounded text-sm">Reset</button>
                        <button id="timeline-export" class="px-3 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded text-sm">Export</button>
                        <button id="timeline-report" class="px-3 py-2 bg-green-600 hover:bg-green-700 text-white rounded text-sm">Generate Report</button>
                        <button id="timeline-add-milestone" class="px-3 py-2 bg-yellow-600 hover:bg-yellow-700 text-white rounded text-sm">Add Milestone</button>
                    </div>
                </div>
                <div id="timeline-stats" class="text-xs text-gray-400 mt-2"></div>
            </div>
        `;
        const timelineHtml = `
            <div class="timeline-visualization mb-6 p-4 bg-gray-800 rounded-lg border border-gray-700">
                <div class="flex items-center justify-between mb-3">
                    <h4 class="text-sm font-semibold text-gray-300">Analysis Timeline</h4>
                    <div class="flex gap-2">
                        <select id="timeline-view-type" class="px-2 py-1 bg-gray-700 hover:bg-gray-600 text-gray-300 rounded text-xs">
                            <option value="gantt">Gantt Chart</option>
                            <option value="sequence">Sequence Diagram</option>
                            <option value="activity">Activity Diagram</option>
                            <option value="milestone">Milestone View</option>
                        </select>
                        <label class="flex items-center gap-1 text-xs text-gray-400">
                            <input type="checkbox" id="timeline-show-dependencies" class="rounded">
                            Dependencies
                        </label>
                        <label class="flex items-center gap-1 text-xs text-gray-400">
                            <input type="checkbox" id="timeline-realtime" class="rounded" checked>
                            Real-time
                        </label>
                    </div>
                </div>
                <div class="timeline-svg-container">
                    <svg id="timeline-svg"></svg>
                </div>
                <div id="dependency-overlay" class="hidden mt-3 p-3 bg-gray-900 rounded border border-gray-700">
                    <h5 class="text-xs font-semibold text-gray-300 mb-2">Dependency Graph</h5>
                    <svg id="dependency-svg" class="w-full h-32"></svg>
                </div>
                <div class="time-scrubber mt-3">
                    <div class="flex items-center gap-2">
                        <span class="text-xs text-gray-400">Time Range:</span>
                        <input type="range" id="timeline-time-scrubber" class="flex-1" min="0" max="100" value="0">
                        <span id="timeline-time-display" class="text-xs text-gray-400 font-mono">0%</span>
                    </div>
                </div>
            </div>
        `;
        const infoHtml = `
            <div class="timeline-info-panel grid grid-cols-1 md:grid-cols-2 gap-4">
                <div class="event-info p-4 bg-gray-800 rounded-lg border border-gray-700">
                    <h4 class="text-sm font-semibold text-gray-300 mb-3">Event Information</h4>
                    <div class="event-details text-gray-400 text-sm" id="event-details">
                        Select an event to see details
                    </div>
                </div>
                <div class="timeline-stats-panel p-4 bg-gray-800 rounded-lg border border-gray-700">
                    <h4 class="text-sm font-semibold text-gray-300 mb-3">Timeline Statistics</h4>
                    <div class="stats-grid grid grid-cols-2 gap-3" id="timeline-stats-panel">
                        ${generateStatsHtml(events)}
                    </div>
                </div>
            </div>
        `;

        const milestonesHtml = `
            <div class="timeline-milestones mt-4 p-4 bg-gray-800 rounded-lg border border-gray-700">
                <div class="flex items-center justify-between mb-3">
                    <h4 class="text-sm font-semibold text-gray-300">Custom Milestones</h4>
                    <button id="timeline-clear-milestones" class="px-2 py-1 bg-red-600 hover:bg-red-700 text-white rounded text-xs">Clear All</button>
                </div>
                <div id="milestones-list" class="space-y-2 max-h-32 overflow-y-auto">
                    <div class="text-xs text-gray-500 text-center">No custom milestones</div>
                </div>
            </div>
        `;

        container.html(controlsHtml + timelineHtml + infoHtml + milestonesHtml);
        setupTimelineHandlers();
        renderD3Timeline(events);
    }
    function processTimelineData(data) {
        if (!data.events) return { events: [] };

        const events = data.events.map(event => ({
            id: event.id,
            title: event.title,
            description: event.description,
            timestamp: event.timestamp,
            duration: event.duration || 0,
            status: event.status || 'pending',
            category: event.category || 'analysis',
            dependencies: event.dependencies || [],
            metadata: event.metadata || {}
        }));

        return { events };
    }
    function generateStatsHtml(events) {
        const total = events.length;
        const completed = events.filter(e => e.status === 'completed').length;
        const inProgress = events.filter(e => e.status === 'in_progress').length;
        const failed = events.filter(e => e.status === 'failed').length;

        const categories = {};
        events.forEach(e => {
            categories[e.category] = (categories[e.category] || 0) + 1;
        });

        return `
            <div class="text-center">
                <div class="text-xl font-bold text-green-400">${completed}</div>
                <div class="text-xs text-gray-400">Completed</div>
            </div>
            <div class="text-center">
                <div class="text-xl font-bold text-blue-400">${inProgress}</div>
                <div class="text-xs text-gray-400">In Progress</div>
            </div>
            <div class="text-center">
                <div class="text-xl font-bold text-red-400">${failed}</div>
                <div class="text-xs text-gray-400">Failed</div>
            </div>
            <div class="text-center">
                <div class="text-xl font-bold text-purple-400">${total}</div>
                <div class="text-xs text-gray-400">Total Events</div>
            </div>
        `;
    }
    function renderD3Timeline(data) {
        if (!data || !data.events || data.events.length === 0) {
            $('#timeline-svg-container').html('<div class="text-center text-gray-500 py-8">No timeline events available</div>');
            return;
        }
        const events = data.events;
        d3.select('#timeline-svg').remove();
        const svg = d3.select('#timeline-svg-container')
            .append('svg')
            .attr('id', 'timeline-svg')
            .attr('width', '100%')
            .attr('height', '400');
        
        let width = $('#timeline-svg-container').width();
        if (!width || isNaN(width) || width === 0) {
            width = 800;
        }
        
        const height = 400;
        const viewType = $('#timeline-view-type').val() || 'gantt';
        svg = d3.select('#timeline-svg')
            .attr('width', '100%')
            .attr('height', height)
            .attr('viewBox', [0, 0, width, height]);
        
        const validEvents = events.filter(e => e.timestamp && !isNaN(e.timestamp));
        if (validEvents.length === 0) {
            $('#timeline-svg-container').html('<div class="text-center text-gray-500 py-8">No valid timeline events available</div>');
            return;
        }
        
        const timestamps = validEvents.map(e => e.timestamp);
        const minTime = Math.min(...timestamps);
        const maxTime = Math.max(...timestamps);
        const timeRange = maxTime - minTime || 1;
        const xScale = d3.scaleLinear()
            .domain([minTime, maxTime])
            .range([50, width - 50]);
        const categories = [...new Set(validEvents.map(e => e.category || 'default'))];
        const yScale = d3.scaleBand()
            .domain(categories)
            .range([50, height - 50])
            .padding(0.3);
        svg.append('g')
            .attr('transform', 'translate(0, 30)')
            .call(d3.axisTop(xScale).tickFormat(d => new Date(d).toLocaleTimeString()));

        svg.append('g')
            .attr('transform', 'translate(40, 0)')
            .call(d3.axisLeft(yScale));
        svg.append('text')
            .attr('x', width / 2)
            .attr('y', 15)
            .attr('text-anchor', 'middle')
            .attr('fill', '#9ca3af')
            .attr('font-size', '12px')
            .text('Time');
        if (viewType === 'gantt') {
            renderGanttChart(events, xScale, yScale, timeRange);
        } else if (viewType === 'sequence') {
            renderSequenceDiagram(events, xScale, yScale, height);
        } else if (viewType === 'activity') {
            renderActivityDiagram(events, xScale, yScale, height);
        } else if (viewType === 'milestone') {
            renderMilestoneView(events, xScale, yScale, height);
        }
        zoom = d3.zoom()
            .scaleExtent([0.5, 3])
            .on('zoom', (event) => {
                svg.select('.timeline-content').attr('transform', event.transform);
            });

        svg.call(zoom);
        svg.selectAll('g').each(function() {
            if (!d3.select(this).classed('axis')) {
                d3.select(this).attr('class', 'timeline-content');
            }
        });
    }
    function renderGanttChart(events, xScale, yScale, timeRange) {
        const g = svg.append('g').attr('class', 'timeline-content');

        events.forEach(event => {
            const x = xScale(event.timestamp);
            const width = Math.max(50, (event.duration / timeRange) * (xScale.range()[1] - xScale.range()[0]));
            const y = yScale(event.category) || 100;

            const rect = g.append('rect')
                .attr('x', x)
                .attr('y', y)
                .attr('width', width)
                .attr('height', yScale.bandwidth())
                .attr('fill', getEventColor(event.status))
                .attr('opacity', 0.7)
                .attr('rx', 4)
                .style('cursor', 'pointer')
                .on('click', () => showEventDetails(event));

            rect.append('title').text(`${event.title}\nStatus: ${event.status}`);

            g.append('text')
                .attr('x', x + 5)
                .attr('y', y + yScale.bandwidth() / 2 + 4)
                .attr('fill', '#e5e7eb')
                .attr('font-size', '10px')
                .text(event.title.length > 15 ? event.title.substring(0, 12) + '...' : event.title);
        });
    }
    function renderSequenceDiagram(events, xScale, yScale, height) {
        const g = svg.append('g').attr('class', 'timeline-content');
        
        const categories = [...new Set(events.map(e => e.category))];
        const categoryWidth = (xScale.range()[1] - xScale.range()[0]) / categories.length;
        categories.forEach((cat, i) => {
            const x = xScale.range()[0] + (i + 0.5) * categoryWidth;
            
            g.append('line')
                .attr('x1', x)
                .attr('y1', 50)
                .attr('x2', x)
                .attr('y2', height - 50)
                .attr('stroke', '#6366f1')
                .attr('stroke-width', 2)
                .attr('stroke-dasharray', '5,5');

            g.append('text')
                .attr('x', x)
                .attr('y', 40)
                .attr('text-anchor', 'middle')
                .attr('fill', '#e5e7eb')
                .attr('font-size', '11px')
                .text(cat);
        });
        events.forEach((event, i) => {
            const sourceIndex = categories.indexOf(event.category);
            const targetIndex = (sourceIndex + 1) % categories.length;
            
            const x1 = xScale.range()[0] + (sourceIndex + 0.5) * categoryWidth;
            const x2 = xScale.range()[0] + (targetIndex + 0.5) * categoryWidth;
            const y = 60 + i * 30;

            g.append('line')
                .attr('x1', x1)
                .attr('y1', y)
                .attr('x2', x2)
                .attr('y2', y)
                .attr('stroke', getEventColor(event.status))
                .attr('stroke-width', 2)
                .attr('marker-end', 'url(#arrowhead)');

            g.append('text')
                .attr('x', (x1 + x2) / 2)
                .attr('y', y - 5)
                .attr('text-anchor', 'middle')
                .attr('fill', '#e5e7eb')
                .attr('font-size', '9px')
                .text(event.title);
        });
    }
    function renderActivityDiagram(events, xScale, yScale, height) {
        const g = svg.append('g').attr('class', 'timeline-content');
        
        events.forEach((event, i) => {
            const x = xScale(event.timestamp);
            const y = 60 + i * 40;

            const circle = g.append('circle')
                .attr('cx', x)
                .attr('cy', y)
                .attr('r', 15)
                .attr('fill', getEventColor(event.status))
                .attr('opacity', 0.8)
                .style('cursor', 'pointer')
                .on('click', () => showEventDetails(event));

            g.append('text')
                .attr('x', x)
                .attr('y', y + 30)
                .attr('text-anchor', 'middle')
                .attr('fill', '#e5e7eb')
                .attr('font-size', '10px')
                .text(event.title.length > 15 ? event.title.substring(0, 12) + '...' : event.title);
        });
    }
    function renderMilestoneView(events, xScale, yScale, height) {
        const g = svg.append('g').attr('class', 'timeline-content');
        
        const completedEvents = events.filter(e => e.status === 'completed');
        
        completedEvents.forEach((event, i) => {
            const x = xScale(event.timestamp);
            const y = height / 2;
            g.append('polygon')
                .attr('points', `${x},${y-15} ${x+15},${y} ${x},${y+15} ${x-15},${y}`)
                .attr('fill', getEventColor(event.status))
                .attr('opacity', 0.8)
                .style('cursor', 'pointer')
                .on('click', () => showEventDetails(event));

            g.append('text')
                .attr('x', x)
                .attr('y', y + 30)
                .attr('text-anchor', 'middle')
                .attr('fill', '#e5e7eb')
                .attr('font-size', '10px')
                .text(event.title.length > 12 ? event.title.substring(0, 10) + '...' : event.title);
        });
    }
    function getEventColor(status) {
        const colors = {
            'completed': '#10b981',
            'in_progress': '#3b82f6',
            'pending': '#6b7280',
            'failed': '#ef4444'
        };
        return colors[status] || colors.pending;
    }
    function showEventDetails(event) {
        const detailsHtml = `
            <div class="space-y-2">
                <div>
                    <div class="text-gray-500">Title</div>
                    <div class="text-gray-300">${event.title}</div>
                </div>
                <div>
                    <div class="text-gray-500">Description</div>
                    <div class="text-gray-300">${event.description || 'N/A'}</div>
                </div>
                <div>
                    <div class="text-gray-500">Timestamp</div>
                    <div class="text-gray-300">${new Date(event.timestamp).toLocaleString()}</div>
                </div>
                <div>
                    <div class="text-gray-500">Duration</div>
                    <div class="text-gray-300">${event.duration}ms</div>
                </div>
                <div>
                    <div class="text-gray-500">Status</div>
                    <div class="text-gray-300 capitalize">${event.status}</div>
                </div>
                <div>
                    <div class="text-gray-500">Category</div>
                    <div class="text-gray-300 capitalize">${event.category}</div>
                </div>
            </div>
        `;

        $('#event-details').html(detailsHtml);
    }
    function setupTimelineHandlers() {
        $('#timeline-search').on('input', filterTimeline);
        $('#timeline-category-filter').on('change', filterTimeline);
        $('#timeline-status-filter').on('change', filterTimeline);
        $('#timeline-view-type').on('change', () => renderD3Timeline(timelineData.events));
        $('#timeline-reset').on('click', resetTimelineFilters);
        $('#timeline-export').on('click', exportTimeline);
        $('#timeline-report').on('click', generateReport);
        $('#timeline-add-milestone').on('click', addCustomMilestone);
        $('#timeline-clear-milestones').on('click', clearMilestones);
        $('#timeline-show-dependencies').on('change', function() {
            if ($(this).is(':checked')) {
                $('#dependency-overlay').removeClass('hidden');
                renderDependencyGraph();
            } else {
                $('#dependency-overlay').addClass('hidden');
            }
            renderD3Timeline(timelineData.events);
        });
        $('#timeline-realtime').on('change', function() {
            if ($(this).is(':checked')) {
                setupWebSocketListeners();
            } else {
                if (window.wsManager) {
                    window.wsManager.off('analysis_progress');
                }
            }
        });
        $('#timeline-time-scrubber').on('input', function() {
            const value = $(this).val();
            $('#timeline-time-display').text(value + '%');
            filterByTimeRange(value);
        });
        loadMilestones();
    }
    function filterTimeline() {
        const searchTerm = $('#timeline-search').val().toLowerCase();
        const categoryFilter = $('#timeline-category-filter').val();
        const statusFilter = $('#timeline-status-filter').val();

        const filteredEvents = originalEvents.filter(event => {
            const matchesSearch = !searchTerm || 
                event.title.toLowerCase().includes(searchTerm) ||
                (event.description && event.description.toLowerCase().includes(searchTerm));
            const matchesCategory = !categoryFilter || event.category === categoryFilter;
            const matchesStatus = !statusFilter || event.status === statusFilter;
            
            return matchesSearch && matchesCategory && matchesStatus;
        });

        renderD3Timeline(filteredEvents);
        updateTimelineStats(filteredEvents);
    }
    function resetTimelineFilters() {
        $('#timeline-search').val('');
        $('#timeline-category-filter').val('');
        $('#timeline-status-filter').val('');
        renderD3Timeline(originalEvents);
        updateTimelineStats(originalEvents);
    }
    function updateTimelineStats(events) {
        const statsHtml = generateStatsHtml(events);
        $('#timeline-stats-panel').html(statsHtml);
        
        const statsText = `Showing ${events.length} of ${originalEvents.length} events`;
        $('#timeline-stats').text(statsText);
    }
    function exportTimeline() {
        if (!timelineData) return;

        const content = JSON.stringify(timelineData, null, 2);
        const blob = new Blob([content], {type: 'application/json'});
        const url = URL.createObjectURL(blob);
        
        const link = document.createElement('a');
        link.href = url;
        link.download = `timeline-${currentJobId}.json`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
    }
    function addTimelineEvent(eventData) {
        if (!timelineData) {
            timelineData = { events: [] };
        }

        const event = processTimelineData({ events: [eventData] }).events[0];
        timelineData.events.push(event);
        originalEvents.push(event);
        
        if ($('#timeline-realtime').is(':checked')) {
            renderD3Timeline(timelineData.events);
            updateTimelineStats(timelineData.events);
        }
    }
    let customMilestones = [];
    function addCustomMilestone() {
        const name = prompt('Enter milestone name:');
        if (!name) return;
        
        const timestamp = Date.now();
        const milestone = {
            id: 'milestone_' + Date.now(),
            name: name,
            timestamp: timestamp,
            description: prompt('Enter description (optional):') || '',
            isCustom: true
        };
        
        customMilestones.push(milestone);
        saveMilestones();
        renderMilestones();
        showToast('Milestone added successfully', 'success');
    }
    function clearMilestones() {
        if (confirm('Are you sure you want to clear all custom milestones?')) {
            customMilestones = [];
            saveMilestones();
            renderMilestones();
        }
    }
    function saveMilestones() {
        localStorage.setItem(`timeline_milestones_${currentJobId}`, JSON.stringify(customMilestones));
    }
    function loadMilestones() {
        const saved = localStorage.getItem(`timeline_milestones_${currentJobId}`);
        if (saved) {
            customMilestones = JSON.parse(saved);
            renderMilestones();
        }
    }
    function renderMilestones() {
        const container = $('#milestones-list');
        
        if (customMilestones.length === 0) {
            container.html('<div class="text-xs text-gray-500 text-center">No custom milestones</div>');
            return;
        }
        
        container.html(customMilestones.map(m => `
            <div class="flex items-center justify-between p-2 bg-gray-900 rounded border border-gray-700">
                <div class="flex-1">
                    <div class="text-xs font-medium text-gray-300">${m.name}</div>
                    <div class="text-xs text-gray-500">${new Date(m.timestamp).toLocaleString()}</div>
                </div>
                <button class="text-red-400 hover:text-red-300 text-xs" onclick="deleteMilestone('${m.id}')">✕</button>
            </div>
        `).join(''));
    }
    window.deleteMilestone = function(id) {
        customMilestones = customMilestones.filter(m => m.id !== id);
        saveMilestones();
        renderMilestones();
    };
    function filterByTimeRange(percentage) {
        if (!timelineData || !timelineData.events) return;
        
        const events = timelineData.events;
        const timestamps = events.map(e => e.timestamp).filter(t => t);
        if (timestamps.length === 0) return;
        
        const minTime = Math.min(...timestamps);
        const maxTime = Math.max(...timestamps);
        const timeRange = maxTime - minTime;
        
        const cutoffTime = minTime + (timeRange * percentage / 100);
        const filtered = events.filter(e => e.timestamp <= cutoffTime);
        
        renderD3Timeline(filtered);
    }
    function generateReport() {
        if (!timelineData) {
            showToast('No timeline data available', 'error');
            return;
        }
        
        const report = {
            jobId: currentJobId,
            generatedAt: new Date().toISOString(),
            statistics: {
                totalEvents: timelineData.events.length,
                completed: timelineData.events.filter(e => e.status === 'completed').length,
                failed: timelineData.events.filter(e => e.status === 'failed').length,
                inProgress: timelineData.events.filter(e => e.status === 'in_progress').length,
                pending: timelineData.events.filter(e => e.status === 'pending').length
            },
            events: timelineData.events,
            milestones: customMilestones
        };
        
        let reportContent = `# Analysis Report\n\n`;
        reportContent += `**Job ID:** ${currentJobId}\n`;
        reportContent += `**Generated:** ${new Date().toLocaleString()}\n\n`;
        reportContent += `## Statistics\n\n`;
        reportContent += `- Total Events: ${report.statistics.totalEvents}\n`;
        reportContent += `- Completed: ${report.statistics.completed}\n`;
        reportContent += `- Failed: ${report.statistics.failed}\n`;
        reportContent += `- In Progress: ${report.statistics.inProgress}\n`;
        reportContent += `- Pending: ${report.statistics.pending}\n\n`;
        reportContent += `## Events\n\n`;
        
        report.events.forEach(e => {
            reportContent += `### ${e.title}\n`;
            reportContent += `- **Status:** ${e.status}\n`;
            reportContent += `- **Category:** ${e.category}\n`;
            reportContent += `- **Time:** ${new Date(e.timestamp).toLocaleString()}\n`;
            if (e.description) {
                reportContent += `- **Description:** ${e.description}\n`;
            }
            reportContent += `\n`;
        });
        
        if (customMilestones.length > 0) {
            reportContent += `## Custom Milestones\n\n`;
            customMilestones.forEach(m => {
                reportContent += `### ${m.name}\n`;
                reportContent += `- **Time:** ${new Date(m.timestamp).toLocaleString()}\n`;
                if (m.description) {
                    reportContent += `- **Description:** ${m.description}\n`;
                }
                reportContent += `\n`;
            });
        }
        
        const blob = new Blob([reportContent], { type: 'text/markdown' });
        const url = URL.createObjectURL(blob);
        
        const link = document.createElement('a');
        link.href = url;
        link.download = `analysis-report-${currentJobId}-${Date.now()}.md`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
        
        showToast('Report generated successfully', 'success');
    }
    function renderDependencyGraph() {
        if (!timelineData || !timelineData.events) return;
        
        const events = timelineData.events;
        const nodes = events.map(e => ({
            id: e.id,
            title: e.title,
            category: e.category,
            timestamp: e.timestamp
        }));
        
        const links = [];
        for (let i = 0; i < events.length - 1; i++) {
            if (events[i].status === 'completed' && events[i + 1].category === events[i].category) {
                links.push({
                    source: events[i].id,
                    target: events[i + 1].id
                });
            }
        }
        
        const svg = d3.select('#dependency-svg');
        svg.selectAll('*').remove();
        
        const width = 400;
        const height = 128;
        svg.attr('width', '100%').attr('height', height);
        
        const simulation = d3.forceSimulation(nodes)
            .force('link', d3.forceLink(links).id(d => d.id).distance(50))
            .force('charge', d3.forceManyBody().strength(-100))
            .force('center', d3.forceCenter(width / 2, height / 2));
        
        const link = svg.append('g')
            .selectAll('line')
            .data(links)
            .enter()
            .append('line')
            .attr('stroke', '#6366f1')
            .attr('stroke-width', 1);
        
        const node = svg.append('g')
            .selectAll('circle')
            .data(nodes)
            .enter()
            .append('circle')
            .attr('r', 5)
            .attr('fill', d => {
                const colors = { analysis: '#10b981', security: '#f59e0b', decompilation: '#8b5cf6', report: '#3b82f6' };
                return colors[d.category] || '#6b7280';
            })
            .attr('stroke', '#fff')
            .attr('stroke-width', 1);
        
        simulation.on('tick', () => {
            link
                .attr('x1', d => d.source.x)
                .attr('y1', d => d.source.y)
                .attr('x2', d => d.target.x)
                .attr('y2', d => d.target.y);
            
            node
                .attr('cx', d => d.x)
                .attr('cy', d => d.y);
        });
    }
    function applyFilters() {
        filterTimeline();
    }
    window.timelineManager = {
        initTimeline: initTimeline,
        renderTimeline: renderTimeline,
        addTimelineEvent: addTimelineEvent
    };
});
