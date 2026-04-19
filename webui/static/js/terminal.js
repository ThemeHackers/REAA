let terminalHistory = [];
let historyIndex = -1;
let currentInput = '';
let jobId = null;
let r2History = [];
let r2HistoryIndex = -1;
let r2CurrentJobId = null;

$(document).ready(function() {
    addTerminalButton();
});

$(window).on('load', function() {
    setTimeout(function() {
        if ($('#terminal-toggle').length === 0 || $('#r2-terminal-toggle').length === 0) {
            addTerminalButton();
        }
    }, 1000);
});

function initTerminal(currentJobId) {
    jobId = currentJobId;
    r2CurrentJobId = currentJobId;
}
    function addTerminalButton() {
        $('#terminal-toggle').remove();
        $('#r2-terminal-toggle').remove();

        let headerContainer = $('.bg-gray-800.border-b.border-gray-700 .flex.items-center.justify-between .flex.items-center.gap-3');
        
        if (headerContainer.length === 0) {
            headerContainer = $('.bg-gray-800.border-b.border-gray-700 .flex.items-center.gap-3');
        }
        
        if (headerContainer.length === 0) {
            const settingsBtn = $('#settings-btn');
            if (settingsBtn.length === 0) {
                return;
            }
            headerContainer = settingsBtn.parent();
        }

        const terminalBtn = $('<button>')
            .attr('id', 'terminal-toggle')
            .addClass('text-sm p-1.5 bg-gray-700 hover:bg-gray-600 text-gray-200 rounded-lg transition cursor-pointer')
            .css('pointer-events', 'auto')
            .attr('title', 'Control Terminal')
            .html('<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"></path></svg>');

        const r2TerminalBtn = $('<button>')
            .attr('id', 'r2-terminal-toggle')
            .addClass('text-sm p-1.5 bg-gray-700 hover:bg-gray-600 text-gray-200 rounded-lg transition cursor-pointer')
            .css('pointer-events', 'auto')
            .attr('title', 'Radare2 Terminal')
            .html('<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"></path></svg>');

        headerContainer.append(terminalBtn);
        headerContainer.append(r2TerminalBtn);

        $('#terminal-toggle').on('click', function(e) {
            e.preventDefault();
            e.stopPropagation();
            toggleTerminal();
        });
        $('#r2-terminal-toggle').on('click', function(e) {
            e.preventDefault();
            e.stopPropagation();
            toggleR2Terminal();
        });
    }
    function toggleTerminal() {
        const terminalContainer = $('#terminal-container');
        if (terminalContainer.length === 0) {
            createTerminalContainer();
        } else {
            terminalContainer.toggle();
        }
    }

    function toggleR2Terminal() {
        const r2TerminalContainer = $('#r2-terminal-container');
        if (r2TerminalContainer.length === 0) {
            createR2TerminalContainer();
        } else {
            r2TerminalContainer.toggle();
        }
    }
    function createTerminalContainer() {
        const savedPosition = JSON.parse(localStorage.getItem('control_terminal_position') || '{}');
        
        if (savedPosition.top && isNaN(parseInt(savedPosition.top))) {
            localStorage.removeItem('control_terminal_position');
        }
        
        const defaultStyle = 'width: 600px; height: 350px; top: 40px; right: 40px;';
        const savedStyle = savedPosition.width && !isNaN(parseInt(savedPosition.top)) && !isNaN(parseInt(savedPosition.right)) ? 
            `width: ${savedPosition.width}px; height: ${savedPosition.height}px; top: ${parseInt(savedPosition.top)}px; right: ${parseInt(savedPosition.right)}px;` : 
            defaultStyle;
        
        const terminalHtml = `
            <div id="terminal-container" class="fixed z-[9999] rounded-lg overflow-hidden bg-gray-900/95 backdrop-blur-xl border border-gray-700/50 shadow-2xl" style="${savedStyle}; display: flex; flex-direction: column; min-width: 500px; min-height: 300px; transform: translateZ(0);">
                <div id="terminal-header" class="flex items-center justify-between px-4 py-3 cursor-move select-none bg-gray-800/50 border-b border-gray-700/50 flex-shrink-0">
                    <div class="flex items-center gap-3">
                        <div class="traffic-lights">
                            <div class="traffic-light close" id="close-terminal"></div>
                            <div class="traffic-light minimize" id="minimize-terminal"></div>
                            <div class="traffic-light maximize" id="maximize-terminal"></div>
                        </div>
                        <span class="text-sm font-semibold text-gray-200 ml-2">Control Terminal</span>
                    </div>
                    <div class="flex gap-2">
                        <button id="clear-terminal" class="px-3 py-1 bg-gray-700/50 hover:bg-gray-600/50 text-gray-300 rounded text-xs transition-all">Clear</button>
                    </div>
                </div>
                <div id="terminal-output" class="flex-1 p-4 overflow-y-auto">
                    <div class="text-green-400 mb-2">AI Reverse Engineering Terminal</div>
                    <div class="text-gray-500 text-sm">Type 'help' for available commands</div>
                </div>
                <div class="flex items-center px-4 py-3 border-t border-white/10 bg-gray-900/50 flex-shrink-0">
                    <span class="text-green-400 mr-2">$</span>
                    <input type="text" id="terminal-input" class="flex-1 bg-transparent border-none outline-none text-sm text-white placeholder-gray-500" placeholder="Enter command...">
                </div>
                <div id="terminal-resize-handle" class="absolute bottom-0 right-0 w-4 h-4 cursor-se-resize rounded-bl-lg"></div>
            </div>
        `;

        $('body').append(terminalHtml);

        $('#close-terminal').on('click', toggleTerminal);
        $('#clear-terminal').on('click', clearTerminal);
        $('#minimize-terminal').on('click', minimizeTerminal);
        $('#maximize-terminal').on('click', maximizeTerminal);
        $('#terminal-input').on('keydown', handleTerminalInput);

        setTimeout(() => $('#terminal-input').focus(), 100);

        makeDraggable('#terminal-container', '#terminal-header', saveControlTerminalPosition);
        makeResizable('#terminal-container', '#terminal-resize-handle', saveControlTerminalPosition);
    }

    function saveControlTerminalPosition() {
        const container = $('#terminal-container');
        const position = {
            width: container.width(),
            height: container.height(),
            top: parseInt(container.css('top')) || 40,
            right: parseInt(container.css('right')) || 40
        };
        localStorage.setItem('control_terminal_position', JSON.stringify(position));
    }

    function createR2TerminalContainer() {
        const savedPosition = JSON.parse(localStorage.getItem('r2_terminal_position') || '{}');
        
        if (savedPosition.top && isNaN(parseInt(savedPosition.top))) {
            localStorage.removeItem('r2_terminal_position');
        }
        
        const defaultStyle = 'width: 600px; height: 350px; top: 40px; right: 40px;';
        const savedStyle = savedPosition.width && !isNaN(parseInt(savedPosition.top)) && !isNaN(parseInt(savedPosition.right)) ? 
            `width: ${savedPosition.width}px; height: ${savedPosition.height}px; top: ${parseInt(savedPosition.top)}px; right: ${parseInt(savedPosition.right)}px;` : 
            defaultStyle;
        
        const r2TerminalHtml = `
            <div id="r2-terminal-container" class="fixed z-[9999] rounded-lg overflow-hidden bg-gray-900/95 backdrop-blur-xl border border-gray-700/50 shadow-2xl" style="${savedStyle}; display: flex; flex-direction: column; min-width: 500px; min-height: 300px; transform: translateZ(0);">
                <div id="r2-terminal-header" class="flex items-center justify-between px-4 py-3 cursor-move select-none bg-gray-800/50 border-b border-gray-700/50 flex-shrink-0">
                    <div class="flex items-center gap-3">
                        <div class="r2-traffic-lights">
                            <div class="r2-traffic-light close" id="r2-close-terminal"></div>
                            <div class="r2-traffic-light minimize" id="r2-minimize-terminal"></div>
                            <div class="r2-traffic-light maximize" id="r2-maximize-terminal"></div>
                        </div>
                        <span class="text-sm font-semibold text-gray-200 ml-2">Radare2 Terminal</span>
                    </div>
                    <div class="flex gap-2">
                        <button id="r2-analyze-selection" class="px-3 py-1 bg-blue-600/50 hover:bg-blue-500/50 text-gray-300 rounded text-xs transition-all">Analyze Selection</button>
                        <button id="r2-clear-terminal" class="px-3 py-1 bg-gray-700/50 hover:bg-gray-600/50 text-gray-300 rounded text-xs transition-all">Clear</button>
                    </div>
                </div>
                <div id="r2-terminal-output" class="flex-1 p-4 overflow-y-auto">
                    <div class="text-red-400 mb-2">Radare2 Terminal</div>
                    <div class="text-gray-500 text-sm">Type 'help' for available Radare2 commands</div>
                </div>
                <div class="flex items-center px-4 py-3 border-t border-white/10 bg-gray-900/50 flex-shrink-0">
                    <span id="r2-prompt" class="mr-2 text-red-400">[0x00000000]></span>
                    <input type="text" id="r2-terminal-input" class="flex-1 bg-transparent border-none outline-none text-sm text-white placeholder-gray-500" placeholder="Enter Radare2 command...">
                </div>
                <div id="r2-terminal-resize-handle" class="absolute bottom-0 right-0 w-4 h-4 cursor-se-resize rounded-bl-lg"></div>
            </div>
        `;

        $('body').append(r2TerminalHtml);

        $('#r2-close-terminal').on('click', toggleR2Terminal);
        $('#r2-clear-terminal').on('click', clearR2Terminal);
        $('#r2-minimize-terminal').on('click', minimizeR2Terminal);
        $('#r2-maximize-terminal').on('click', maximizeR2Terminal);
        $('#r2-analyze-selection').on('click', function(e) {
            e.preventDefault();
            e.stopPropagation();
            analyzeSelectedCode();
        });
        $('#r2-terminal-input').on('keydown', handleR2TerminalInput);

        setTimeout(() => $('#r2-terminal-input').focus(), 100);

        makeDraggable('#r2-terminal-container', '#r2-terminal-header', saveR2TerminalPosition);
        makeResizable('#r2-terminal-container', '#r2-terminal-resize-handle', saveR2TerminalPosition);

        autoLoadCurrentJob();
    }

    function saveR2TerminalPosition() {
        const container = $('#r2-terminal-container');
        const position = {
            width: container.width(),
            height: container.height(),
            top: parseInt(container.css('top')) || 40,
            right: parseInt(container.css('right')) || 40
        };
        localStorage.setItem('r2_terminal_position', JSON.stringify(position));
    }

    function autoLoadCurrentJob() {
        if (typeof currentJobId !== 'undefined' && currentJobId) {
            loadR2File(currentJobId);
        } else {
            $.get('/api/jobs', function(data) {
                if (data.jobs && data.jobs.length > 0) {
                    loadR2File(data.jobs[0].id);
                }
            });
        }
    }

    function updateR2Prompt(address) {
        r2CurrentAddress = address || '0x00000000';
        $('#r2-prompt').text(`[${r2CurrentAddress}]>`);
    }

    let controlTerminalState = {
        isMinimized: false,
        isMaximized: false,
        originalSize: { width: 600, height: 400, bottom: 20, right: 20 }
    };

    let r2TerminalState = {
        isMinimized: false,
        isMaximized: false,
        originalSize: { width: 600, height: 400, bottom: 20, right: 640 }
    };

    function minimizeTerminal() {
        const container = $('#terminal-container');
        const body = $('#terminal-body');
        const state = controlTerminalState;
        
        if (!state.isMinimized) {
            state.originalSize = {
                width: container.width(),
                height: container.height(),
                bottom: parseInt(container.css('bottom')),
                right: parseInt(container.css('right'))
            };
            body.hide();
            container.css({ height: 'auto', width: '300px' });
            state.isMinimized = true;
            state.isMaximized = false;
        } else {
            body.show();
            container.css({
                height: state.originalSize.height + 'px',
                width: state.originalSize.width + 'px',
                bottom: state.originalSize.bottom + 'px',
                right: state.originalSize.right + 'px'
            });
            state.isMinimized = false;
        }
    }

    function maximizeTerminal() {
        const container = $('#terminal-container');
        const body = $('#terminal-body');
        const state = controlTerminalState;
        
        if (!state.isMaximized) {
            state.originalSize = {
                width: container.width(),
                height: container.height(),
                bottom: parseInt(container.css('bottom')),
                right: parseInt(container.css('right'))
            };
            body.show();
            container.css({
                width: '100%',
                height: '100%',
                bottom: '0',
                right: '0',
                top: '0',
                left: '0',
                borderRadius: '0'
            });
            state.isMaximized = true;
            state.isMinimized = false;
        } else {
            body.show();
            container.css({
                width: state.originalSize.width + 'px',
                height: state.originalSize.height + 'px',
                bottom: state.originalSize.bottom + 'px',
                right: state.originalSize.right + 'px',
                top: 'auto',
                left: 'auto',
                borderRadius: '0.5rem'
            });
            state.isMaximized = false;
        }
    }

    function minimizeR2Terminal() {
        const container = $('#r2-terminal-container');
        const body = $('#r2-terminal-body');
        const state = r2TerminalState;
        
        if (!state.isMinimized) {
            state.originalSize = {
                width: container.width(),
                height: container.height(),
                bottom: parseInt(container.css('bottom')),
                right: parseInt(container.css('right'))
            };
            body.hide();
            container.css({ height: 'auto', width: '300px' });
            state.isMinimized = true;
            state.isMaximized = false;
        } else {
            body.show();
            container.css({
                height: state.originalSize.height + 'px',
                width: state.originalSize.width + 'px',
                bottom: state.originalSize.bottom + 'px',
                right: state.originalSize.right + 'px'
            });
            state.isMinimized = false;
        }
    }

    function maximizeR2Terminal() {
        const container = $('#r2-terminal-container');
        const body = $('#r2-terminal-body');
        const state = r2TerminalState;
        
        if (!state.isMaximized) {
            state.originalSize = {
                width: container.width(),
                height: container.height(),
                bottom: parseInt(container.css('bottom')),
                right: parseInt(container.css('right'))
            };
            body.show();
            container.css({
                width: '100%',
                height: '100%',
                bottom: '0',
                right: '0',
                top: '0',
                left: '0',
                borderRadius: '0'
            });
            state.isMaximized = true;
            state.isMinimized = false;
        } else {
            body.show();
            container.css({
                width: state.originalSize.width + 'px',
                height: state.originalSize.height + 'px',
                bottom: state.originalSize.bottom + 'px',
                right: state.originalSize.right + 'px',
                top: 'auto',
                left: 'auto',
                borderRadius: '0.5rem'
            });
            state.isMaximized = false;
        }
    }

    function makeDraggable(containerId, headerId, onDragEnd = null) {
        const container = $(containerId);
        const header = $(headerId);
        let isDragging = false;
        let startX, startY, initialX, initialY;

        header.on('mousedown', function(e) {
            const state = containerId === '#terminal-container' ? controlTerminalState : r2TerminalState;
            if (state.isMaximized) return;
            isDragging = true;
            startX = e.clientX;
            startY = e.clientY;
            initialX = container.offset().left;
            initialY = container.offset().top;
            header.css('cursor', 'grabbing');
        });

        $(document).on('mousemove', function(e) {
            if (!isDragging) return;
            const dx = e.clientX - startX;
            const dy = e.clientY - startY;
            
            const newX = initialX + dx;
            const newY = initialY + dy;
            
            const maxX = $(window).width() - container.width();
            const maxY = $(window).height() - container.height();
            
            container.css({
                left: Math.max(0, Math.min(newX, maxX)) + 'px',
                top: Math.max(0, Math.min(newY, maxY)) + 'px',
                right: 'auto',
                bottom: 'auto'
            });
        });

        $(document).on('mouseup', function() {
            if (isDragging && onDragEnd) {
                onDragEnd();
            }
            isDragging = false;
            header.css('cursor', 'move');
        });
    }

    function makeResizable(containerId, handleId, onResizeEnd = null) {
        const container = $(containerId);
        const handle = $(handleId);
        let isResizing = false;
        let startX, startY, startWidth, startHeight;

        handle.on('mousedown', function(e) {
            const state = containerId === '#terminal-container' ? controlTerminalState : r2TerminalState;
            if (state.isMaximized) return;
            isResizing = true;
            startX = e.clientX;
            startY = e.clientY;
            startWidth = container.width();
            startHeight = container.height();
            e.preventDefault();
        });

        $(document).on('mousemove', function(e) {
            if (!isResizing) return;
            const dx = e.clientX - startX;
            const dy = e.clientY - startY;
            
            const newWidth = Math.max(500, startWidth - dx);
            const newHeight = Math.max(300, startHeight - dy);
            
            container.css({
                width: newWidth + 'px',
                height: newHeight + 'px'
            });
        });

        $(document).on('mouseup', function() {
            if (isResizing && onResizeEnd) {
                onResizeEnd();
            }
            isResizing = false;
        });
    }
    function setupTerminalHandlers() {
    }

    function handleR2TerminalInput(event) {
        const input = $('#r2-terminal-input');
        const command = input.val();

        if (event.key === 'Enter') {
            if (command.trim()) {
                executeR2Command(command.trim());
            }
            input.val('');
        } else if (event.key === 'ArrowUp') {
            event.preventDefault();
            if (r2HistoryIndex > 0) {
                r2HistoryIndex--;
                input.val(r2History[r2HistoryIndex]);
            }
        } else if (event.key === 'ArrowDown') {
            event.preventDefault();
            if (r2HistoryIndex < r2History.length - 1) {
                r2HistoryIndex++;
                input.val(r2History[r2HistoryIndex]);
            } else {
                r2HistoryIndex = r2History.length;
                input.val('');
            }
        }
    }

    let r2CurrentAddress = '0x00000000';

    function executeR2Command(command) {
        const output = $('#r2-terminal-output');
        const parts = command.split(' ');
        const cmd = parts[0].toLowerCase();
        const args = parts.slice(1);
        output.append(`<div class="text-red-400">[${r2CurrentAddress}]> ${escapeHtml(command)}</div>`);
        r2History.push(command);
        r2HistoryIndex = r2History.length;

        switch (cmd) {
            case 'help':
                output.append(`
                    <div class="text-gray-300">Available Radare2 commands:</div>
                    <div class="text-gray-400 ml-4">help - Show this help message</div>
                    <div class="text-gray-400 ml-4">clear - Clear terminal</div>
                    <div class="text-gray-400 ml-4">load [job_id] - Load file from job into Radare2</div>
                    <div class="text-gray-400 ml-4">aaa - Analyze all functions</div>
                    <div class="text-cyan-400 ml-4 mt-2">--- Navigation ---</div>
                    <div class="text-gray-400 ml-4">s [addr] - Seek to address</div>
                    <div class="text-gray-400 ml-4">s+ [offset] - Seek forward</div>
                    <div class="text-gray-400 ml-4">s- [offset] - Seek backward</div>
                    <div class="text-gray-400 ml-4">pd [num] - Print disassembly</div>
                    <div class="text-gray-400 ml-4">pdf - Print disassembly of function</div>
                    <div class="text-gray-400 ml-4">px [len] - Print hexdump</div>
                    <div class="text-gray-400 ml-4">ps [len] - Print string</div>
                    <div class="text-cyan-400 ml-4 mt-2">--- Analysis ---</div>
                    <div class="text-gray-400 ml-4">aa - Analyze function at current address</div>
                    <div class="text-gray-400 ml-4">aac - Analyze function calls</div>
                    <div class="text-gray-400 ml-4">aar - Analyze all references</div>
                    <div class="text-gray-400 ml-4">afl - List all functions</div>
                    <div class="text-gray-400 ml-4">afn [name] - Name function</div>
                    <div class="text-gray-400 ml-4">afvn [old] [new] - Rename variable</div>
                    <div class="text-gray-400 ml-4">afsr - Analyze stack references</div>
                    <div class="text-cyan-400 ml-4 mt-2">--- Information ---</div>
                    <div class="text-gray-400 ml-4">i - Show binary info</div>
                    <div class="text-gray-400 ml-4">ii - Show imports</div>
                    <div class="text-gray-400 ml-4">ie - Show entrypoints</div>
                    <div class="text-gray-400 ml-4">iE - Show entrypoints (verbose)</div>
                    <div class="text-gray-400 ml-4">is - Show sections</div>
                    <div class="text-gray-400 ml-4">iS - Show symbols</div>
                    <div class="text-gray-400 ml-4">iz - Show strings</div>
                    <div class="text-cyan-400 ml-4 mt-2">--- Flags ---</div>
                    <div class="text-gray-400 ml-4">f [name] [addr] - Set flag at address</div>
                    <div class="text-gray-400 ml-4">f- [name] - Remove flag</div>
                    <div class="text-gray-400 ml-4">f. - List current flags</div>
                    <div class="text-gray-400 ml-4">fc [addr] - Flag current address</div>
                    <div class="text-cyan-400 ml-4 mt-2">--- Comments ---</div>
                    <div class="text-gray-400 ml-4">CC [comment] - Add comment at current address</div>
                    <div class="text-gray-400 ml-4">CC- [comment] - Remove comment</div>
                    <div class="text-gray-400 ml-4">CC. - Show comment at current address</div>
                    <div class="text-cyan-400 ml-4 mt-2">--- Search ---</div>
                    <div class="text-gray-400 ml-4">/ [pattern] - Search for string</div>
                    <div class="text-gray-400 ml-4">/x [hex] - Search for hex pattern</div>
                    <div class="text-gray-400 ml-4">/c [pattern] - Search for case-insensitive string</div>
                    <div class="text-gray-400 ml-4">/a [asm] - Search for assembly</div>
                    <div class="text-cyan-400 ml-4 mt-2">--- Visual ---</div>
                    <div class="text-gray-400 ml-4">V - Enter visual mode</div>
                    <div class="text-gray-400 ml-4">VV - Enter visual panel mode</div>
                    <div class="text-gray-400 ml-4">V! - Enter visual debug mode</div>
                    <div class="text-cyan-400 ml-4 mt-2">--- Debug ---</div>
                    <div class="text-gray-400 ml-4">doo - Start debug</div>
                    <div class="text-gray-400 ml-4">db [addr] - Set breakpoint</div>
                    <div class="text-gray-400 ml-4">db- [addr] - Remove breakpoint</div>
                    <div class="text-gray-400 ml-4">dc - Continue execution</div>
                    <div class="text-gray-400 ml-4">ds - Step into</div>
                    <div class="text-gray-400 ml-4">dso - Step over</div>
                    <div class="text-cyan-400 ml-4 mt-2">--- Binary ---</div>
                    <div class="text-gray-400 ml-4">o [file] - Open file</div>
                    <div class="text-gray-400 ml-4">oo - Reopen file</div>
                    <div class="text-gray-400 ml-4">o+ [file] - Open file in read-write</div>
                    <div class="text-gray-400 ml-4">q - Quit</div>
                    <div class="text-gray-400 ml-4">q! - Quit without saving</div>
                    <div class="text-gray-400 ml-4">exit - Close terminal</div>
                    <div class="text-cyan-400 ml-4 mt-2">--- AI Commands ---</div>
                    <div class="text-gray-400 ml-4">decompile - Decompile current function</div>
                    <div class="text-gray-400 ml-4">decompile [query] - Ask question about function</div>
                    <div class="text-gray-400 ml-4">decompile [lang] - Decompile to specific language (c, python, js, php)</div>
                    <div class="text-gray-400 ml-4">explain - Explain current function</div>
                    <div class="text-gray-400 ml-4">vulns - Find vulnerabilities in current function</div>
                    <div class="text-gray-400 ml-4">autoname - Suggest better function name</div>
                    <div class="text-gray-400 ml-4">varnames - Better variable names</div>
                    <div class="text-gray-400 ml-4">signature - Suggest function signature</div>
                    <div class="text-gray-400 ml-4">devices - Find and explain devices used</div>
                    <div class="text-gray-400 ml-4">libs - Group imports by libraries</div>
                    <div class="text-gray-400 ml-4">auto [query] - Auto mode with function calling</div>
                    <div class="text-gray-400 ml-4">chat - Enter AI chat mode</div>
                    <div class="text-gray-400 ml-4">ai [prompt] - Send custom prompt to AI</div>
                `);
                break;

            case 'clear':
                clearR2Terminal();
                output.append('<div class="text-red-400">Terminal cleared</div>');
                break;

            case 'load':
                if (args.length > 0) {
                    loadR2File(args[0]);
                } else {
                    output.append('<div class="text-red-400">Error: Job ID required</div>');
                    output.append('<div class="text-gray-500">Usage: load [job_id]</div>');
                }
                break;

            case 'aaa':
            case 'afl':
            case 'pdf':
            case 'ii':
            case 'ie':
            case 'iz':
            case 'iI':
            case 'px':
                if (!r2CurrentJobId) {
                    output.append('<div class="text-red-400">Error: No file loaded. Use "load [job_id]" first</div>');
                } else {
                    executeR2BackendCommand(command);
                }
                break;

            case 'exit':
                toggleR2Terminal();
                break;

            default:
                if (!r2CurrentJobId) {
                    output.append('<div class="text-red-400">Error: No file loaded. Use "load [job_id]" first</div>');
                } else {
                    executeR2BackendCommand(command);
                }
        }
        output.scrollTop(output[0].scrollHeight);
    }

    function loadR2File(jobId) {
        const output = $('#r2-terminal-output');
        output.append(`<div class="text-yellow-400">Loading file for job ${jobId}...</div>`);
        
        const token = localStorage.getItem('token');
        const headers = {
            'Authorization': `Bearer ${token}`
        };
        
        $.ajax({
            url: '/api/r2/load',
            method: 'POST',
            contentType: 'application/json',
            headers: headers,
            data: JSON.stringify({ job_id: jobId }),
            success: function(data) {
                if (data.success) {
                    r2CurrentJobId = jobId;
                    output.append('<div class="text-green-400">File loaded successfully into Radare2</div>');
                    output.append(`<div class="text-gray-400">File: ${data.filename || 'unknown'}</div>`);
                    
                    if (data.entry_point) {
                        updateR2Prompt(data.entry_point);
                        output.append(`<div class="text-gray-400">Entry point: ${data.entry_point}</div>`);
                    } else if (data.base_address) {
                        updateR2Prompt(data.base_address);
                        output.append(`<div class="text-gray-400">Base address: ${data.base_address}</div>`);
                    }
                } else {
                    output.append(`<div class="text-red-400">Error: ${data.error}</div>`);
                }
            },
            error: function(xhr) {
                output.append(`<div class="text-red-400">Error: ${xhr.responseJSON?.error || 'Failed to load file'}</div>`);
            }
        });
    }

    function executeR2BackendCommand(command) {
        const output = $('#r2-terminal-output');
        
        const token = localStorage.getItem('token');
        const headers = {
            'Authorization': `Bearer ${token}`
        };
        
        $.ajax({
            url: '/api/r2/command',
            method: 'POST',
            contentType: 'application/json',
            headers: headers,
            data: JSON.stringify({ 
                command: command,
                job_id: r2CurrentJobId 
            }),
            success: function(data) {
                if (data.success) {
                    if (data.output) {
                        if (command.startsWith('s ')) {
                            const addrMatch = command.match(/s\s+(0x[0-9a-fA-F]+)/);
                            if (addrMatch) {
                                updateR2Prompt(addrMatch[1]);
                            }
                        }
                        
                        if (command.startsWith('pd') || command.startsWith('pdf')) {
                            const firstAddrMatch = data.output.match(/0x[0-9a-fA-F]+/);
                            if (firstAddrMatch) {
                                updateR2Prompt(firstAddrMatch[0]);
                            }
                        }
                        
                        const formattedOutput = formatAsmLine(data.output);
                        output.append(`<div class="whitespace-pre font-mono text-sm">${formattedOutput}</div>`);
                    }
                } else {
                    output.append(`<div class="text-red-400">Error: ${data.error}</div>`);
                }
            },
            error: function(xhr) {
                output.append(`<div class="text-red-400">Error: ${xhr.responseJSON?.error || 'Command execution failed'}</div>`);
            }
        });
    }

    function formatAsmLine(line) {
        let formatted = escapeHtml(line);
        
        formatted = formatted.replace(/\b(0x[0-9a-fA-F]+)\b/g, '<span class="text-cyan-400">$1</span>');
        
        formatted = formatted.replace(/\b(fcn\.[0-9a-fA-F]+)\b/g, '<span class="text-purple-400">$1</span>');
        formatted = formatted.replace(/\b(sym\.[a-zA-Z0-9_]+)\b/g, '<span class="text-purple-400">$1</span>');
        formatted = formatted.replace(/\b(str\.[a-zA-Z0-9_]+)\b/g, '<span class="text-pink-400">$1</span>');
        
        const instructions = ['mov', 'push', 'pop', 'call', 'ret', 'jmp', 'je', 'jne', 'jg', 'jl', 'jge', 'jle', 'cmp', 'test', 'add', 'sub', 'mul', 'div', 'xor', 'and', 'or', 'not', 'shl', 'shr', 'lea', 'nop', 'int', 'inc', 'dec', 'leave', 'enter', 'and', 'sub', 'test'];
        const instrRegex = new RegExp(`\\b(${instructions.join('|')})\\b`, 'gi');
        formatted = formatted.replace(instrRegex, '<span class="text-green-400">$1</span>');
        
        const registers = ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp', 'eip', 'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp', 'rip', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'ax', 'bx', 'cx', 'dx', 'si', 'di', 'bp', 'sp', 'ip', 'al', 'bl', 'cl', 'dl', 'ah', 'bh', 'ch', 'dh'];
        const regRegex = new RegExp(`\\b(${registers.join('|')})\\b`, 'gi');
        formatted = formatted.replace(regRegex, '<span class="text-yellow-400">$1</span>');
        
        return formatted;
    }
    
    function seekToAddress(address) {
        const input = $('#r2-terminal-input');
        input.val(`s ${address}`);
        input.focus();
    }
    
    function seekToFunction(functionName) {
        const input = $('#r2-terminal-input');
        input.val(`s ${functionName}`);
        input.focus();
    }

    function clearR2Terminal() {
        const output = $('#r2-terminal-output');
        output.empty();
        output.append('<div class="text-red-400">Radare2 Terminal</div>');
        output.append('<div class="text-gray-500">Type \'help\' for available Radare2 commands</div>');
    }

    function analyzeSelectedCode() {
        const selection = window.getSelection().toString().trim();
        
        if (!selection) {
            alert('Please select some ASM code to analyze');
            return;
        }

        if (!r2CurrentJobId) {
            if (typeof currentJobId !== 'undefined' && currentJobId) {
                r2CurrentJobId = currentJobId;
            } else {
                alert('No active job found. Please load a file first.');
                return;
            }
        }

        const output = $('#r2-terminal-output');
        const loadingId = 'loading-' + Date.now();
        output.append(`
            <div id="${loadingId}" class="text-blue-400 mt-2">
                <div class="flex items-center">
                    <div class="animate-spin rounded-full h-4 w-4 border-b-2 border-blue-400 mr-2"></div>
                    <span>Analyzing selected code with AI agent...</span>
                </div>
            </div>
        `);
        output.scrollTop(output[0].scrollHeight);
        
        const token = localStorage.getItem('token');
        const headers = {
            'Authorization': `Bearer ${token}`
        };
        
        $.ajax({
            url: '/api/asm/analyze',
            method: 'POST',
            contentType: 'application/json',
            headers: headers,
            data: JSON.stringify({
                code: selection,
                job_id: r2CurrentJobId
            }),
            success: function(data) {
                $(`#${loadingId}`).remove();
                if (data.analysis) {
                    const output = $('#r2-terminal-output');
                    
                    output.append(`<div class="text-blue-400 font-bold mt-4 mb-2 border-t border-blue-800 pt-2">--- ASM Analysis ---</div>`);
                    
                    let formattedAnalysis = data.analysis
                        .replace(/\n{3,}/g, '\n\n')
                        .replace(/[ \t]+$/gm, '')
                        .replace(/^## (.+)$/gm, '<div class="text-cyan-400 font-bold mt-3 mb-2">$1</div>')
                        .replace(/^### (.+)$/gm, '<div class="text-green-400 font-semibold mt-2 mb-1">$1</div>')
                        .replace(/^- (.+)$/gm, '<div class="text-yellow-300 ml-4">- $1</div>')
                        .replace(/\*\*([^*]+)\*\*/g, '<span class="text-orange-400 font-semibold">$1</span>')
                        .replace(/^(\d+)\. (.+)$/gm, '<div class="text-gray-300 ml-2">$1. $2</div>')
                        .replace(/^\s*$/gm, '<div class="mb-1"></div>')
                        .replace(/  +/g, ' ')
                        .replace(/\n/g, '<br>');
                    
                    output.append(`<div class="text-gray-300 text-sm leading-relaxed">${formattedAnalysis}</div>`);
                    output.scrollTop(output[0].scrollHeight);
                }
            },
            error: function(xhr) {
                $(`#${loadingId}`).remove();
                output.append(`<div class="text-red-400 mt-2">Analysis failed: ${xhr.responseJSON?.error || 'Unknown error'}</div>`);
                output.scrollTop(output[0].scrollHeight);
            }
        });
    }
    function handleTerminalInput(event) {
        const input = $('#terminal-input');
        const command = input.val();

        if (event.key === 'Enter') {
            if (command.trim()) {
                executeCommand(command.trim());
                terminalHistory.push(command);
                historyIndex = terminalHistory.length;
            }
            input.val('');
        } else if (event.key === 'ArrowUp') {
            event.preventDefault();
            if (historyIndex > 0) {
                historyIndex--;
                input.val(terminalHistory[historyIndex]);
            }
        } else if (event.key === 'ArrowDown') {
            event.preventDefault();
            if (historyIndex < terminalHistory.length - 1) {
                historyIndex++;
                input.val(terminalHistory[historyIndex]);
            } else {
                historyIndex = terminalHistory.length;
                input.val('');
            }
        }
    }
    function executeCommand(command) {
        const output = $('#terminal-output');
        const parts = command.split(' ');
        const cmd = parts[0].toLowerCase();
        const args = parts.slice(1);
        output.append(`<div class="text-green-400">$ ${escapeHtml(command)}</div>`);
        switch (cmd) {
            case 'help':
                output.append(`
                    <div class="text-gray-300">Available commands:</div>
                    <div class="text-gray-400 ml-4">help - Show this help message</div>
                    <div class="text-gray-400 ml-4">clear - Clear terminal</div>
                    <div class="text-gray-400 ml-4">jobs - List all jobs</div>
                    <div class="text-gray-400 ml-4">status [job_id] - Show job status</div>
                    <div class="text-gray-400 ml-4">analyze [file] - Start analysis</div>
                    <div class="text-gray-400 ml-4">export [job_id] - Export analysis results</div>
                    <div class="text-gray-400 ml-4">exit - Close terminal</div>
                `);
                break;

            case 'clear':
                clearTerminal();
                output.append('<div class="text-green-400">Terminal cleared</div>');
                break;

            case 'jobs':
                fetchJobs();
                break;

            case 'status':
                if (args.length > 0) {
                    fetchJobStatus(args[0]);
                } else if (jobId) {
                    fetchJobStatus(jobId);
                } else {
                    output.append('<div class="text-red-400">Error: Job ID required</div>');
                }
                break;

            case 'analyze':
                if (args.length > 0) {
                    startAnalysis(args[0]);
                } else {
                    output.append('<div class="text-red-400">Error: File path required</div>');
                }
                break;

            case 'export':
                if (args.length > 0) {
                    exportResults(args[0]);
                } else if (jobId) {
                    exportResults(jobId);
                } else {
                    output.append('<div class="text-red-400">Error: Job ID required</div>');
                }
                break;

            
            default:
                if (cmd.startsWith('/')) {
                    executeR2BackendCommand(command);
                } else {
                    output.append(`<div class="text-red-400">Unknown command: ${escapeHtml(cmd)}</div>`);
                    output.append('<div class="text-gray-500">Type "help" for available commands</div>');
                }
                break;
        }
        output.scrollTop(output[0].scrollHeight);
    }
    function fetchJobs() {
        const output = $('#terminal-output');
        $.get('/api/jobs', function(data) {
            output.append('<div class="text-gray-300">Jobs:</div>');
            data.jobs.forEach(job => {
                output.append(`<div class="text-gray-400 ml-4">ID: ${job.id}, File: ${job.filename}, Status: ${job.status}</div>`);
            });
        }).fail(function(xhr) {
            output.append('<div class="text-red-400">Error: Failed to fetch jobs</div>');
        });
    }
    function fetchJobStatus(jobId) {
        const output = $('#terminal-output');
        $.get(`/api/jobs/${jobId}/status`, function(data) {
            output.append(`<div class="text-gray-300">Job ${jobId} Status:</div>`);
            output.append(`<div class="text-gray-400 ml-4">Progress: ${data.progress}%</div>`);
            output.append(`<div class="text-gray-400 ml-4">Status: ${data.status}</div>`);
            if (data.message) {
                output.append(`<div class="text-gray-400 ml-4">Message: ${data.message}</div>`);
            }
        }).fail(function(xhr) {
            output.append('<div class="text-red-400">Error: Failed to fetch job status</div>');
        });
    }
    function startAnalysis(filePath) {
        const output = $('#terminal-output');
        output.append(`<div class="text-gray-300">Starting analysis for: ${escapeHtml(filePath)}</div>`);
        output.append('<div class="text-yellow-400">Analysis start not yet implemented</div>');
    }
    function exportResults(jobId) {
        const output = $('#terminal-output');
        output.append(`<div class="text-gray-300">Exporting results for job: ${jobId}</div>`);
        output.append('<div class="text-yellow-400">Export not yet implemented</div>');
    }
    function clearTerminal() {
        const output = $('#terminal-output');
        output.empty();
        output.append('<div class="text-green-400">AI Reverse Engineering Terminal</div>');
        output.append('<div class="text-gray-500">Type "help" for available commands</div>');
    }

    function setupTerminalHandlers() {
    }

    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    function handleDecompileCommand(args, output) {
        if (args.length === 0) {
            const prompt = 'Decompile the current function to C programming language. Provide clean, readable code with proper variable names, types, and comments. Include function signature and explain the logic.';
            sendAiCommand(prompt, output, 'Decompilation to C');
            return;
        }

        const firstArg = args[0].toLowerCase();
        const remainingArgs = args.slice(1).join(' ');
        
        const languages = ['c', 'cpp', 'c++', 'python', 'py', 'javascript', 'js', 'java', 'php', 'rust', 'go'];
        if (languages.includes(firstArg)) {
            const langMap = {
                'c': 'C', 'cpp': 'C++', 'c++': 'C++',
                'python': 'Python', 'py': 'Python',
                'javascript': 'JavaScript', 'js': 'JavaScript',
                'java': 'Java', 'php': 'PHP', 'rust': 'Rust', 'go': 'Go'
            };
            const targetLang = langMap[firstArg];
            const query = remainingArgs || `Decompile this function to ${targetLang}`;
            const prompt = `Decompile the current function to ${targetLang} programming language. ${query}. Provide clean, readable code with proper variable names, types, and comments. Include function signature and explain the logic.`;
            sendAiCommand(prompt, output, `Decompilation to ${targetLang}`);
        } else {
            const query = args.join(' ');
            const prompt = `Analyze the current function and answer this question: ${query}. Provide detailed technical explanation with code examples if relevant. Focus on the function's purpose, logic, and behavior.`;
            sendAiCommand(prompt, output, 'Function Analysis');
        }
    }

    function handleExplainCommand(output) {
        const prompt = 'Explain the current function in detail. What does it do? What is its purpose? How does it work? Include analysis of the algorithm, data flow, and any interesting patterns or techniques used.';
        sendAiCommand(prompt, output, 'Function Explanation');
    }

    function handleVulnsCommand(output) {
        const prompt = 'Analyze the current function for security vulnerabilities and potential risks. Look for buffer overflows, integer overflows, format string vulnerabilities, use-after-free, race conditions, injection vulnerabilities, and other security issues. Provide specific recommendations for fixing any identified vulnerabilities.';
        sendAiCommand(prompt, output, 'Vulnerability Analysis');
    }

    function handleAutonameCommand(output) {
        const prompt = 'Analyze the current function and suggest a better, more descriptive name based on what the function actually does. Consider its purpose, parameters, return value, and overall functionality. Provide 3-5 alternative names with explanations for each suggestion.';
        sendAiCommand(prompt, output, 'Function Naming');
    }

    function handleVarnamesCommand(output) {
        const prompt = 'Analyze the current function and suggest better variable names for all local variables, parameters, and temporaries. The new names should be descriptive and follow good naming conventions. Provide a mapping of old names to new names with explanations.';
        sendAiCommand(prompt, output, 'Variable Naming');
    }

    function handleSignatureCommand(output) {
        const prompt = 'Analyze the current function and suggest an accurate function signature including parameter names, types, and return type. Consider the calling convention, number and types of parameters, and what the function returns. Provide the signature in C/C++ format with explanations.';
        sendAiCommand(prompt, output, 'Function Signature');
    }

    function handleDevicesCommand(output) {
        const prompt = 'Analyze the current function and identify any hardware devices, system resources, or external dependencies it interacts with. Look for file handles, network sockets, device I/O, system calls, registry access, or other resource usage. Explain how each device/resource is used.';
        sendAiCommand(prompt, output, 'Device Analysis');
    }

    function handleLibsCommand(output) {
        const prompt = 'Analyze the current function and identify which libraries or external modules it depends on. Group the imports/dependencies by library and explain what each library provides. Look for standard library calls, third-party libraries, system APIs, and any dynamic linking.';
        sendAiCommand(prompt, output, 'Library Analysis');
    }

    function handleAutoCommand(args, output) {
        const query = args.join(' ') || 'Analyze this function comprehensively';
        const prompt = `You are an expert reverse engineer. ${query}. Use your knowledge to automatically analyze the current function, identify key patterns, and provide insights. You may ask follow-up questions or suggest additional analysis steps if needed.`;
        sendAiCommand(prompt, output, 'Auto Analysis');
    }

    function handleChatCommand(output) {
        output.append('<div class="text-blue-400">Entering AI chat mode. Type your questions about the current function.</div>');
        output.append('<div class="text-gray-500">Type "exit" to leave chat mode.</div>');
        const prompt = 'Hello! I\'m ready to help you analyze this function. What would you like to know?';
        sendAiCommand(prompt, output, 'AI Chat');
    }

    function handleAiCommand(args, output) {
        if (args.length === 0) {
            output.append('<div class="text-red-400">Error: Prompt required for ai command</div>');
            return;
        }
        const prompt = args.join(' ');
        sendAiCommand(prompt, output, 'Custom AI Query');
    }

    function sendAiCommand(prompt, output, title) {
        if (!r2CurrentJobId) {
            output.append('<div class="text-red-400">Error: No active job found. Please load a file first.</div>');
            return;
        }

        const loadingId = `loading-${Date.now()}`;
        output.append(`<div id="${loadingId}" class="text-yellow-400 mt-2">
            <div class="inline-block animate-spin rounded-full h-4 w-4 border-b-2 border-yellow-400"></div>
            ${title} in progress...
        </div>`);

        const token = localStorage.getItem('token');
        const headers = {
            'Authorization': `Bearer ${token}`
        };
        
        $.ajax({
            url: '/api/r2/command',
            method: 'POST',
            contentType: 'application/json',
            headers: headers,
            data: JSON.stringify({
                job_id: r2CurrentJobId,
                command: 'pdf'
            }),
            success: function(data) {
                if (data.success && data.output) {
                    const context = data.output;
                    const fullPrompt = `Current function context:\n${context}\n\n${prompt}`;
                    
                    $.ajax({
                        url: '/api/asm/analyze',
                        method: 'POST',
                        contentType: 'application/json',
                        headers: headers,
                        data: JSON.stringify({
                            code: context,
                            job_id: r2CurrentJobId,
                            prompt: fullPrompt
                        }),
                        success: function(analysisData) {
                            $(`#${loadingId}`).remove();
                            if (analysisData.success && analysisData.analysis) {
                                const formattedAnalysis = analysisData.analysis
                                    .replace(/&lt;/g, '<')
                                    .replace(/&gt;/g, '>')
                                    .replace(/&amp;/g, '&')
                                    .replace(/\n{3,}/g, '\n\n')
                                    .replace(/[ \t]+$/gm, '')
                                    .replace(/^## (.+)$/gm, '<div class="text-cyan-400 font-bold mt-3 mb-2">$1</div>')
                                    .replace(/^### (.+)$/gm, '<div class="text-green-400 font-semibold mt-2 mb-1">$1</div>')
                                    .replace(/^- (.+)$/gm, '<div class="text-yellow-300 ml-4">- $1</div>')
                                    .replace(/\*\*([^*]+)\*\*/g, '<span class="text-orange-400 font-semibold">$1</span>')
                                    .replace(/^(\d+)\. (.+)$/gm, '<div class="text-gray-300 ml-2">$1. $2</div>')
                                    .replace(/^\s*$/gm, '<div class="mb-1"></div>')
                                    .replace(/  +/g, ' ')
                                    .replace(/\n/g, '<br>');
                                
                                output.append(`<div class="text-blue-400 font-bold mt-4 mb-2 border-t border-blue-800 pt-2">--- ${title} ---</div>`);
                                output.append(`<div class="text-gray-300 text-sm leading-relaxed">${formattedAnalysis}</div>`);
                                output.scrollTop(output[0].scrollHeight);
                            } else {
                                $(`#${loadingId}`).remove();
                                output.append(`<div class="text-red-400 mt-2">Analysis failed: ${analysisData.error || 'Unknown error'}</div>`);
                            }
                        },
                        error: function(xhr) {
                            $(`#${loadingId}`).remove();
                            output.append(`<div class="text-red-400 mt-2">Analysis failed: ${xhr.responseJSON?.error || 'Unknown error'}</div>`);
                            output.scrollTop(output[0].scrollHeight);
                        }
                    });
                } else {
                    $(`#${loadingId}`).remove();
                    output.append('<div class="text-red-400">Error: Failed to get function context</div>');
                }
            },
            error: function(xhr) {
                $(`#${loadingId}`).remove();
                output.append('<div class="text-red-400">Error: Failed to communicate with Radare2</div>');
            }
        });
    }
