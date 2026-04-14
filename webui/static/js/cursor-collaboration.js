class CursorCollaborationManager {
    constructor() {
        this.remoteCursors = new Map();
        this.myCursorId = null;
        this.currentJobId = null;
        this.socket = null;
        
        this.initialize();
    }
    
    initialize() {
        this.createCursorContainer();
        
        this.trackMouseMovements();
        
        this.trackScrollPositions();
        
        this.trackTextSelection();
    }
    
    createCursorContainer() {
        if ($('#cursor-container').length === 0) {
            $('body').append('<div id="cursor-container" class="fixed inset-0 pointer-events-none z-40"></div>');
        }
    }
    
    trackMouseMovements() {
        let lastPosition = { x: 0, y: 0 };
        let lastSentTime = 0;
        const throttleMs = 50;
        
        $(document).on('mousemove', (e) => {
            const now = Date.now();
            
            if (now - lastSentTime > throttleMs) {
                const position = { x: e.clientX, y: e.clientY };
                
                const dx = Math.abs(position.x - lastPosition.x);
                const dy = Math.abs(position.y - lastPosition.y);
                
                if (dx > 5 || dy > 5) {
                    this.broadcastCursor('mouse', position);
                    lastPosition = position;
                    lastSentTime = now;
                }
            }
        });
    }
    
    trackScrollPositions() {
        let lastScrollTop = 0;
        let lastSentTime = 0;
        const throttleMs = 100;
        
        $(window).on('scroll', () => {
            const now = Date.now();
            
            if (now - lastSentTime > throttleMs) {
                const scrollTop = $(window).scrollTop();
                
                if (Math.abs(scrollTop - lastScrollTop) > 50) {
                    this.broadcastCursor('scroll', { scrollTop: scrollTop });
                    lastScrollTop = scrollTop;
                    lastSentTime = now;
                }
            }
        });
    }
    
    trackTextSelection() {
        $(document).on('mouseup', () => {
            const selection = window.getSelection();
            if (selection.toString().length > 0) {
                const range = selection.getRangeAt(0);
                const rect = range.getBoundingClientRect();
                
                this.broadcastCursor('selection', {
                    text: selection.toString(),
                    x: rect.left,
                    y: rect.top,
                    width: rect.width,
                    height: rect.height
                });
            }
        });
    }
    
    broadcastCursor(type, data) {
        if (!this.socket || !this.currentJobId) return;
        
        this.socket.emit('cursor_update', {
            job_id: this.currentJobId,
            type: type,
            data: data,
            timestamp: Date.now()
        });
    }
    
    handleRemoteCursor(data) {
        const userId = data.user_id;
        const username = data.username || 'Anonymous';
        const type = data.type;
        const cursorData = data.data;
        
        let cursor = this.remoteCursors.get(userId);
        
        if (!cursor) {
            cursor = this.createRemoteCursor(userId, username);
            this.remoteCursors.set(userId, cursor);
        }
        
        switch (type) {
            case 'mouse':
                this.updateMouseCursor(cursor, cursorData);
                break;
            case 'scroll':
                this.updateScrollIndicator(cursor, cursorData);
                break;
            case 'selection':
                this.updateSelectionHighlight(cursor, cursorData);
                break;
            case 'node':
                this.updateNodeHighlight(cursor, cursorData);
                break;
        }
        
        cursor.lastActivity = Date.now();
        
        this.scheduleCursorRemoval(userId, cursor);
    }
    
    createRemoteCursor(userId, username) {
        const colors = [
            '#ef4444', '#f59e0b', '#10b981', '#3b82f6', 
            '#8b5cf6', '#ec4899', '#06b6d4', '#84cc16'
        ];
        const colorIndex = userId.split('').reduce((acc, char) => acc + char.charCodeAt(0), 0) % colors.length;
        const color = colors[colorIndex];
        
        const cursor = $(`
            <div id="cursor-${userId}" class="remote-cursor absolute transition-all duration-100" style="z-index: 1000;">
                <div class="cursor-pointer" style="background-color: ${color};">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="${color}">
                        <path d="M5.5 3.21V20.8c0 .45.54.67.85.35l4.86-4.86a.5.5 0 0 1 .35-.15h6.87c.48 0 .72-.58.38-.92L5.94 2.35a.5.5 0 0 0-.44.86z"/>
                    </svg>
                </div>
                <div class="cursor-label text-xs px-2 py-1 rounded text-white" style="background-color: ${color};">
                    ${username}
                </div>
            </div>
        `);
        
        $('#cursor-container').append(cursor);
        
        return {
            element: cursor,
            color: color,
            username: username,
            lastActivity: Date.now()
        };
    }
    
    updateMouseCursor(cursor, data) {
        cursor.element.css({
            left: data.x + 'px',
            top: data.y + 'px'
        });
        
        cursor.element.removeClass('hidden');
        cursor.element.find('.cursor-selection').remove();
    }
    
    updateScrollIndicator(cursor, data) {
        let indicator = cursor.element.find('.scroll-indicator');
        
        if (indicator.length === 0) {
            indicator = $(`
                <div class="scroll-indicator absolute right-0 w-2 rounded" style="background-color: ${cursor.color}; height: 20px;"></div>
            `);
            cursor.element.append(indicator);
        }
        
        const scrollPercent = data.scrollTop / ($(document).height() - $(window).height());
        const indicatorTop = scrollPercent * ($(window).height() - 20);
        
        indicator.css({
            top: indicatorTop + 'px',
            right: '10px'
        });
        
        setTimeout(() => {
            indicator.fadeOut();
        }, 2000);
    }
    
    updateSelectionHighlight(cursor, data) {
        cursor.element.find('.cursor-selection').remove();
        
        const selection = $(`
            <div class="cursor-selection absolute border-2 rounded" style="
                left: ${data.x}px;
                top: ${data.y}px;
                width: ${data.width}px;
                height: ${data.height}px;
                border-color: ${cursor.color};
                background-color: ${cursor.color}20;
            "></div>
        `);
        
        cursor.element.append(selection);
        
        const tooltip = $(`
            <div class="selection-tooltip absolute text-xs px-2 py-1 rounded bg-gray-800 text-white" style="
                left: ${data.x}px;
                top: ${data.y - 30}px;
            ">
                Selected: "${data.text.substring(0, 30)}${data.text.length > 30 ? '...' : ''}"
            </div>
        `);
        
        cursor.element.append(tooltip);
        
        setTimeout(() => {
            selection.fadeOut(() => selection.remove());
            tooltip.fadeOut(() => tooltip.remove());
        }, 3000);
    }
    
    updateNodeHighlight(cursor, nodeId) {
        if (window.graphVisualization) {
            window.graphVisualization.centerOnNode(nodeId);
        }
        
        const indicator = $(`
            <div class="node-indicator absolute px-3 py-1 rounded text-white text-sm" style="
                background-color: ${cursor.color};
                top: 50%;
                left: 50%;
                transform: translate(-50%, -50%);
            ">
                ${cursor.username} is viewing node
            </div>
        `);
        
        cursor.element.append(indicator);
        
        setTimeout(() => {
            indicator.fadeOut(() => indicator.remove());
        }, 2000);
    }
    
    scheduleCursorRemoval(userId, cursor) {
        if (cursor.removeTimeout) {
            clearTimeout(cursor.removeTimeout);
        }
        
        cursor.removeTimeout = setTimeout(() => {
            const now = Date.now();
            if (now - cursor.lastActivity > 10000) {
                this.removeRemoteCursor(userId);
            }
        }, 10000);
    }
    
    removeRemoteCursor(userId) {
        const cursor = this.remoteCursors.get(userId);
        if (cursor) {
            cursor.element.remove();
            this.remoteCursors.delete(userId);
        }
    }
    
    setSocket(socket) {
        this.socket = socket;
        
        this.socket.on('cursor_update', (data) => {
            this.handleRemoteCursor(data);
        });
        
        this.socket.on('user_left', (data) => {
            this.removeRemoteCursor(data.user_id);
        });
    }
    
    setCurrentJob(jobId) {
        this.currentJobId = jobId;
        
        this.remoteCursors.forEach((cursor, userId) => {
            this.removeRemoteCursor(userId);
        });
    }
    
    clearAllCursors() {
        this.remoteCursors.forEach((cursor, userId) => {
            this.removeRemoteCursor(userId);
        });
    }
    
    destroy() {
        this.clearAllCursors();
        $('#cursor-container').remove();
    }
}

$(document).ready(() => {
    window.cursorCollaborationManager = new CursorCollaborationManager();
    
    if (window.remoteCollaborationManager) {
        const originalConnectAsClient = window.remoteCollaborationManager.connectAsClient.bind(window.remoteCollaborationManager);
        
        window.remoteCollaborationManager.connectAsClient = function(...args) {
            const result = originalConnectAsClient(...args);
            
            if (this.remoteSocket) {
                window.cursorCollaborationManager.setSocket(this.remoteSocket);
            }
            
            return result;
        };
        
        const originalJoinRemoteJob = window.remoteCollaborationManager.joinRemoteJob.bind(window.remoteCollaborationManager);
        
        window.remoteCollaborationManager.joinRemoteJob = function(jobId) {
            const result = originalJoinRemoteJob(jobId);
            
            window.cursorCollaborationManager.setCurrentJob(jobId);
            
            return result;
        };
    }
});
