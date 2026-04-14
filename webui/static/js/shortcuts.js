$(document).ready(function() {
    const shortcuts = {
        'Ctrl+Shift+T': () => toggleR2Terminal(),
        'Ctrl+Shift+C': () => toggleTerminal(),
        'Ctrl+L': () => clearCurrentTerminal(),
        'Escape': () => closeModals(),
        'F1': () => showHelp(),
        '?': () => showHelp()
    };

    function initShortcuts() {
        $(document).on('keydown', handleKeydown);
    }

    function handleKeydown(event) {
        if ($(event.target).is('input, textarea')) {
            return;
        }

        const key = buildKeyString(event);
        
        if (shortcuts[key]) {
            event.preventDefault();
            try {
                shortcuts[key]();
            } catch (error) {
                console.error('Error executing shortcut:', key, error);
            }
        }
    }

    function buildKeyString(event) {
        const parts = [];
        
        if (event.ctrlKey) parts.push('Ctrl');
        if (event.altKey) parts.push('Alt');
        if (event.shiftKey) parts.push('Shift');
        if (event.metaKey) parts.push('Meta');
        
        parts.push(event.key);
        
        return parts.join('+');
    }

    function toggleR2Terminal() {
        const container = $('#r2-terminal-container');
        if (container.length > 0) {
            if (container.is(':visible')) {
                container.hide();
            } else {
                container.show();
                $('#r2-terminal-input').focus();
            }
        }
    }

    function toggleTerminal() {
        const container = $('#terminal-container');
        if (container.length > 0) {
            if (container.is(':visible')) {
                container.hide();
            } else {
                container.show();
                $('#terminal-input').focus();
            }
        }
    }

    function clearCurrentTerminal() {
        const r2Terminal = $('#r2-terminal-container');
        const controlTerminal = $('#terminal-container');
        
        if (r2Terminal.is(':visible')) {
            $('#r2-terminal-output').empty();
            $('#r2-terminal-output').append('<div class="text-red-400">Radare2 Terminal</div>');
            $('#r2-terminal-output').append('<div class="text-gray-500">Type \'help\' for available Radare2 commands</div>');
        }
        
        if (controlTerminal.is(':visible')) {
            $('#terminal-output').empty();
            $('#terminal-output').append('<div class="text-green-400">AI Reverse Engineering Terminal</div>');
            $('#terminal-output').append('<div class="text-gray-500">Type "help" for available commands</div>');
        }
    }

    function closeModals() {
        $('.modal').hide();
        $('#r2-terminal-container').hide();
        $('#terminal-container').hide();
    }

    function showHelp() {
        $('#help-modal').remove();
        
        const helpHtml = `
            <div class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-[10000]" id="help-modal">
                <div class="bg-gray-800 rounded-lg p-6 max-w-2xl w-full mx-4 border border-gray-700 max-h-[80vh] overflow-y-auto shadow-2xl">
                    <div class="flex justify-between items-center mb-4">
                        <h3 class="text-lg font-semibold text-gray-300">Keyboard Shortcuts</h3>
                        <button class="text-gray-400 hover:text-white text-2xl" onclick="$('#help-modal').remove()">✕</button>
                    </div>
                    <div class="space-y-4">
                        <div>
                            <h4 class="text-sm font-medium text-cyan-400 mb-2">Terminal</h4>
                            <ul class="text-sm text-gray-300 space-y-1">
                                <li><kbd class="bg-gray-700 px-2 py-1 rounded text-xs">Ctrl+Shift+T</kbd> - Toggle Radare2 Terminal</li>
                                <li><kbd class="bg-gray-700 px-2 py-1 rounded text-xs">Ctrl+Shift+C</kbd> - Toggle Control Terminal</li>
                                <li><kbd class="bg-gray-700 px-2 py-1 rounded text-xs">Ctrl+L</kbd> - Clear Terminal</li>
                            </ul>
                        </div>
                        <div>
                            <h4 class="text-sm font-medium text-cyan-400 mb-2">General</h4>
                            <ul class="text-sm text-gray-300 space-y-1">
                                <li><kbd class="bg-gray-700 px-2 py-1 rounded text-xs">Escape</kbd> - Close Modals/Terminals</li>
                                <li><kbd class="bg-gray-700 px-2 py-1 rounded text-xs">F1</kbd> or <kbd class="bg-gray-700 px-2 py-1 rounded text-xs">?</kbd> - Show Help</li>
                            </ul>
                        </div>
                    </div>
                </div>
            </div>
        `;

        $('body').append(helpHtml);
        
        $('#help-modal').on('click', function(e) {
            if (e.target.id === 'help-modal') {
                $('#help-modal').remove();
            }
        });
    }

    function registerShortcut(key, callback) {
        shortcuts[key] = callback;
    }

    function unregisterShortcut(key) {
        delete shortcuts[key];
    }

    window.shortcutsManager = {
        initShortcuts: initShortcuts,
        registerShortcut: registerShortcut,
        unregisterShortcut: unregisterShortcut
    };

    initShortcuts();
});
