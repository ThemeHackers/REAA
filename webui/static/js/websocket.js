$(document).ready(function() {
    let socket = null;
    let reconnectAttempts = 0;
    const maxReconnectAttempts = 5;
    let eventHandlers = {};
    function initWebSocket() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}`;
        
        try {
            socket = io(wsUrl, {
                transports: ['websocket', 'polling'],
                reconnection: true,
                reconnectionAttempts: maxReconnectAttempts,
                reconnectionDelay: 1000
            });

            setupSocketListeners();
        } catch (error) {
            console.error('Failed to initialize WebSocket:', error);
        }
    }
    function setupSocketListeners() {
        if (!socket) return;

        socket.on('connect', () => {
            reconnectAttempts = 0;
            triggerEvent('connected', { connected: true });
        });

        socket.on('disconnect', (reason) => {
            triggerEvent('disconnected', { reason });
        });

        socket.on('connect_error', (error) => {
            console.error('Socket.IO connection error:', error);
            reconnectAttempts++;
            triggerEvent('connect_error', { error, attempts: reconnectAttempts });
        });

        socket.on('reconnect', (attemptNumber) => {
            triggerEvent('reconnected', { attempts: attemptNumber });
        });

        socket.on('reconnect_failed', () => {
            console.error('Socket.IO reconnection failed');
            triggerEvent('reconnect_failed', { attempts: reconnectAttempts });
        });

        socket.on('message', (data) => {
            triggerEvent('message', data);
        });

        socket.on('error', (error) => {
            console.error('Socket.IO error:', error);
            triggerEvent('error', error);
        });
        socket.on('analysis_progress', (data) => {
            triggerEvent('analysis_progress', data);
        });

        socket.on('analysis_complete', (data) => {
            triggerEvent('analysis_complete', data);
        });

        socket.on('analysis_error', (data) => {
            console.error('Analysis error:', data);
            triggerEvent('analysis_error', data);
        });

        socket.on('job_update', (data) => {
            triggerEvent('job_update', data);
        });

        socket.on('log_message', (data) => {
            triggerEvent('log_message', data);
        });
    }
    function on(event, callback) {
        if (!eventHandlers[event]) {
            eventHandlers[event] = [];
        }
        eventHandlers[event].push(callback);
    }
    function off(event, callback) {
        if (eventHandlers[event]) {
            eventHandlers[event] = eventHandlers[event].filter(cb => cb !== callback);
        }
    }
    function triggerEvent(event, data) {
        if (eventHandlers[event]) {
            eventHandlers[event].forEach(callback => {
                try {
                    callback(data);
                } catch (error) {
                    console.error(`Error in event handler for ${event}:`, error);
                }
            });
        }
    }
    function emit(event, data) {
        if (socket && socket.connected) {
            socket.emit(event, data);
        } else {
            console.warn('Socket not connected, cannot emit event:', event);
        }
    }
    function disconnect() {
        if (socket) {
            socket.disconnect();
        }
    }
    function isConnected() {
        return socket && socket.connected;
    }
    window.wsManager = {
        initWebSocket: initWebSocket,
        on: on,
        off: off,
        emit: emit,
        disconnect: disconnect,
        isConnected: isConnected
    };
    initWebSocket();
});
