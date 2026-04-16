$(document).ready(function() {
    let currentJobId = null;
    function initExport(jobId) {
        currentJobId = jobId;
        setupExportHandlers();
    }
    function setupExportHandlers() {
        $('#export-btn').on('click', showExportDialog);
    }
    function showExportDialog() {
        const savedSettings = JSON.parse(localStorage.getItem('export_settings') || '{}');
        
        const exportHtml = `
            <div class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50" id="export-dialog">
                <div class="bg-gray-800 rounded-lg p-6 max-w-md w-full mx-4 border border-gray-700">
                    <div class="flex justify-between items-center mb-4">
                        <h3 class="text-lg font-semibold text-gray-300">Export Analysis Results</h3>
                        <button class="text-gray-400 hover:text-white" onclick="$('#export-dialog').remove()">✕</button>
                    </div>
                    <div class="space-y-4">
                        <div>
                            <label class="block text-sm font-medium text-gray-300 mb-2">Export Format</label>
                            <select id="export-format" class="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-gray-200 text-sm focus:outline-none focus:border-blue-500">
                                <option value="json" ${savedSettings.format === 'json' ? 'selected' : ''}>JSON</option>
                                <option value="xml" ${savedSettings.format === 'xml' ? 'selected' : ''}>XML</option>
                                <option value="csv" ${savedSettings.format === 'csv' ? 'selected' : ''}>CSV</option>
                                <option value="pdf" ${savedSettings.format === 'pdf' ? 'selected' : ''}>PDF Report</option>
                            </select>
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-300 mb-2">Include Sections</label>
                            <div class="space-y-2">
                                <label class="flex items-center">
                                    <input type="checkbox" id="export-analysis-summary" ${savedSettings.analysis_summary !== false ? 'checked' : ''} class="mr-2">
                                    <span class="text-sm text-gray-300">Analysis Summary</span>
                                </label>
                                <label class="flex items-center">
                                    <input type="checkbox" id="export-security-findings" ${savedSettings.security_findings !== false ? 'checked' : ''} class="mr-2">
                                    <span class="text-sm text-gray-300">Security Findings</span>
                                </label>
                                <label class="flex items-center">
                                    <input type="checkbox" id="export-code-structure" ${savedSettings.code_structure !== false ? 'checked' : ''} class="mr-2">
                                    <span class="text-sm text-gray-300">Code Structure</span>
                                </label>
                                <label class="flex items-center">
                                    <input type="checkbox" id="export-chat-history" ${savedSettings.chat_history !== false ? 'checked' : ''} class="mr-2">
                                    <span class="text-sm text-gray-300">Chat History</span>
                                </label>
                                <label class="flex items-center">
                                    <input type="checkbox" id="export-memory" ${savedSettings.memory !== false ? 'checked' : ''} class="mr-2">
                                    <span class="text-sm text-gray-300">Memory Layout</span>
                                </label>
                                <label class="flex items-center">
                                    <input type="checkbox" id="export-strings" ${savedSettings.strings !== false ? 'checked' : ''} class="mr-2">
                                    <span class="text-sm text-gray-300">Strings</span>
                                </label>
                                <label class="flex items-center">
                                    <input type="checkbox" id="export-imports" ${savedSettings.imports !== false ? 'checked' : ''} class="mr-2">
                                    <span class="text-sm text-gray-300">Imports/Exports</span>
                                </label>
                            </div>
                        </div>
                        <div class="flex gap-2">
                            <button id="do-export" class="flex-1 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded text-sm">Export</button>
                            <button id="cancel-export" class="flex-1 px-4 py-2 bg-gray-700 hover:bg-gray-600 text-gray-200 rounded text-sm">Cancel</button>
                        </div>
                    </div>
                </div>
            </div>
        `;

        $('body').append(exportHtml);

        $('#cancel-export').on('click', () => $('#export-dialog').remove());
        $('#do-export').on('click', performExport);
        
        $('#export-dialog input[type="checkbox"], #export-dialog select').on('change', saveExportSettings);
    }
    
    function saveExportSettings() {
        const settings = {
            format: $('#export-format').val(),
            analysis_summary: $('#export-analysis-summary').is(':checked'),
            security_findings: $('#export-security-findings').is(':checked'),
            code_structure: $('#export-code-structure').is(':checked'),
            chat_history: $('#export-chat-history').is(':checked'),
            memory: $('#export-memory').is(':checked'),
            strings: $('#export-strings').is(':checked'),
            imports: $('#export-imports').is(':checked')
        };
        localStorage.setItem('export_settings', JSON.stringify(settings));
    }
    function performExport() {
        const format = $('#export-format').val();
        const sections = {
            analysis_summary: $('#export-analysis-summary').is(':checked'),
            security_findings: $('#export-security-findings').is(':checked'),
            code_structure: $('#export-code-structure').is(':checked'),
            chat_history: $('#export-chat-history').is(':checked'),
            memory: $('#export-memory').is(':checked'),
            strings: $('#export-strings').is(':checked'),
            imports: $('#export-imports').is(':checked')
        };
        const exportData = {};

        exportData.metadata = {
            job_id: currentJobId,
            generated: new Date().toISOString(),
            format: format
        };

        if (sections.analysis_summary) {
            exportData.analysis_summary = {
                title: "Analysis Summary",
                content: "Analysis summary will be generated based on the selected sections."
            };
            checkExportComplete();
        }

        if (sections.security_findings) {
            exportData.security_findings = {
                title: "Security Findings",
                content: "Security findings will be generated based on the analysis."
            };
            checkExportComplete();
        }

        if (sections.code_structure) {
            exportData.code_structure = {
                title: "Code Structure",
                content: "Code structure analysis will be generated based on the binary analysis."
            };
            checkExportComplete();
        }

        if (sections.chat_history) {
            $.get(`/api/chat/history/${currentJobId}`, function(data) {
                exportData.chat_history = {
                    title: "Chat History",
                    messages: data.messages || []
                };
                checkExportComplete();
            }).fail(() => {
                exportData.chat_history = {
                    title: "Chat History",
                    messages: []
                };
                checkExportComplete();
            });
        }

        if (sections.memory) {
            $.get(`/api/jobs/${currentJobId}/memory`, function(data) {
                exportData.memory = data;
                checkExportComplete();
            }).fail(() => checkExportComplete());
        }

        if (sections.strings) {
            $.get(`/api/jobs/${currentJobId}/strings`, function(data) {
                exportData.strings = data;
                checkExportComplete();
            }).fail(() => checkExportComplete());
        }

        if (sections.imports) {
            $.get(`/api/jobs/${currentJobId}/imports`, function(data) {
                exportData.imports = data;
                checkExportComplete();
            }).fail(() => checkExportComplete());
        }
        let fetchedSections = 0;
        const totalSections = Object.values(sections).filter(v => v).length;

        function checkExportComplete() {
            fetchedSections++;
            if (fetchedSections >= totalSections) {
                downloadExport(exportData, format);
            }
        }

        if (totalSections === 0) {
            alert('Please select at least one section to export');
            return;
        }
    }
    function downloadExport(data, format) {
        let content, filename, mimeType;

        switch (format) {
            case 'json':
                content = JSON.stringify(data, null, 2);
                filename = `analysis-${currentJobId}.json`;
                mimeType = 'application/json';
                break;
            case 'xml':
                content = jsonToXml(data);
                filename = `analysis-${currentJobId}.xml`;
                mimeType = 'application/xml';
                break;
            case 'csv':
                content = jsonToCsv(data);
                filename = `analysis-${currentJobId}.csv`;
                mimeType = 'text/csv';
                break;
            case 'pdf':
                content = generatePdfReport(data);
                filename = `analysis-${currentJobId}.pdf`;
                mimeType = 'application/pdf';
                break;
            default:
                content = JSON.stringify(data, null, 2);
                filename = `analysis-${currentJobId}.json`;
                mimeType = 'application/json';
        }

        const blob = new Blob([content], { type: mimeType });
        const url = URL.createObjectURL(blob);
        
        const link = document.createElement('a');
        link.href = url;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);

        $('#export-dialog').remove();
    }
    function jsonToXml(obj) {
        let xml = '<?xml version="1.0" encoding="UTF-8"?>\n<analysis>\n';
        
        function traverse(obj, indent = 1) {
            let result = '';
            const pad = '  '.repeat(indent);
            
            for (const key in obj) {
                if (obj.hasOwnProperty(key)) {
                    const value = obj[key];
                    if (Array.isArray(value)) {
                        result += `${pad}<${key}>\n`;
                        value.forEach(item => {
                            if (typeof item === 'object') {
                                result += traverse(item, indent + 1);
                            } else {
                                result += `${pad}  <item>${item}</item>\n`;
                            }
                        });
                        result += `${pad}</${key}>\n`;
                    } else if (typeof value === 'object') {
                        result += `${pad}<${key}>\n`;
                        result += traverse(value, indent + 1);
                        result += `${pad}</${key}>\n`;
                    } else {
                        result += `${pad}<${key}>${value}</${key}>\n`;
                    }
                }
            }
            
            return result;
        }
        
        xml += traverse(obj);
        xml += '</analysis>';
        return xml;
    }
    function jsonToCsv(data) {
        let csv = '';
        
        function flatten(obj, prefix = '') {
            let result = {};
            for (const key in obj) {
                if (obj.hasOwnProperty(key)) {
                    const newKey = prefix ? `${prefix}.${key}` : key;
                    if (typeof obj[key] === 'object' && obj[key] !== null) {
                        Object.assign(result, flatten(obj[key], newKey));
                    } else {
                        result[newKey] = obj[key];
                    }
                }
            }
            return result;
        }
        
        const flattened = flatten(data);
        const headers = Object.keys(flattened);
        csv += headers.join(',') + '\n';
        csv += headers.map(h => flattened[h]).join(',') + '\n';
        
        return csv;
    }
    function generatePdfReport(data) {
        let report = 'ANALYSIS REPORT\n';
        report += '================\n\n';
        report += `Job ID: ${currentJobId}\n`;
        report += `Generated: ${new Date().toISOString()}\n\n`;
        
        if (data.metadata) {
            report += 'METADATA\n';
            report += '--------\n';
            report += `Job ID: ${data.metadata.job_id}\n`;
            report += `Generated: ${data.metadata.generated}\n`;
            report += `Format: ${data.metadata.format}\n\n`;
        }
        
        if (data.analysis_summary) {
            report += 'ANALYSIS SUMMARY\n';
            report += '----------------\n';
            report += `${data.analysis_summary.content}\n\n`;
        }
        
        if (data.security_findings) {
            report += 'SECURITY FINDINGS\n';
            report += '-----------------\n';
            report += `${data.security_findings.content}\n\n`;
        }
        
        if (data.code_structure) {
            report += 'CODE STRUCTURE\n';
            report += '--------------\n';
            report += `${data.code_structure.content}\n\n`;
        }
        
        if (data.chat_history) {
            report += 'CHAT HISTORY\n';
            report += '------------\n';
            if (data.chat_history.messages && data.chat_history.messages.length > 0) {
                data.chat_history.messages.forEach((msg, i) => {
                    report += `[${i+1}] ${msg.role}: ${msg.content}\n`;
                });
            } else {
                report += 'No chat history available.\n';
            }
            report += '\n';
        }
        
        if (exportSettings.technical) {
            if (data.memory) {
                report += 'MEMORY LAYOUT\n';
                report += '-------------\n';
                report += JSON.stringify(data.memory, null, 2) + '\n\n';
            }
            
            if (data.controlflow) {
                report += 'CONTROL FLOW GRAPH\n';
                report += '------------------\n';
                report += JSON.stringify(data.controlflow, null, 2) + '\n\n';
            }
            
            if (data.strings) {
                report += 'STRINGS\n';
                report += '-------\n';
                report += JSON.stringify(data.strings, null, 2) + '\n\n';
            }
            
            if (data.imports) {
                report += 'IMPORTS/EXPORTS\n';
                report += '---------------\n';
                report += JSON.stringify(data.imports, null, 2) + '\n\n';
            }
            report += 'CONTROL FLOW GRAPH\n';
            report += '------------------\n';
            report += JSON.stringify(data.controlflow, null, 2) + '\n\n';
        }
        
        if (data.strings) {
            report += 'STRINGS\n';
            report += '-------\n';
            report += JSON.stringify(data.strings, null, 2) + '\n\n';
        }
        
        if (data.imports) {
            report += 'IMPORTS/EXPORTS\n';
            report += '---------------\n';
            report += JSON.stringify(data.imports, null, 2) + '\n\n';
        }
        
        return report;
    }
    window.exportManager = {
        initExport: initExport,
        showExportDialog: showExportDialog,
        performExport: performExport
    };
});
