class RemoteCollaborationManager {
    constructor() {
        this.remoteSocket = null;
        this.isConnected = false;
        this.currentRoom = null;
        this.currentUser = this.generateUserId();
        this.remoteJobs = new Map();
        this.connectedUsers = new Map();
        this.connectionMode = 'client';
        this.serverConnectedClients = 0;
        this.serverStatusInterval = null;
        this.jobSyncInterval = null;
        this.updateRemoteJobsListDebounce = null;


        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 10;
        this.reconnectDelay = 1000;
        this.reconnectTimeout = null;
        this.authErrorOccurred = false;


        this.latency = 0;
        this.latencyHistory = [];
        this.latencyCheckInterval = null;
        this.pingStartTime = null;
        this.roomUsersSyncInterval = null;

        this.initializeEventListeners();
        this.loadSavedSettings();
    }

    generateUserId() {
        return 'user_' + Math.random().toString(36).substr(2, 9);
    }
    
    initializeEventListeners() {
        $('#remote-settings-btn').on('click', () => this.showRemoteSettings());
        
        $('#close-remote-settings').on('click', () => this.hideRemoteSettings());
        
        $('#connect-remote').on('click', () => this.connectToRemote());
        
        $('#disconnect-remote').on('click', () => this.disconnectFromRemote());
        
        $('#remote-connection-mode').on('change', function() {
            this.toggleModeFields();
            this.updateConnectButtonText();
            this.updateApiKeysVisibility();
        }.bind(this));
        
        $('#remote-settings-modal').on('click', (e) => {
            if (e.target.id === 'remote-settings-modal') {
                this.hideRemoteSettings();
            }
        });
        
        $('#generate-api-key-btn').on('click', () => this.generateApiKey());
    }
    
    async loadApiKeys() {
        try {
            const response = await fetch('/api/remote/api-keys');
            if (response.ok) {
                const data = await response.json();
                this.renderApiKeys(data.api_keys);
            }
        } catch (error) {
            console.error('Failed to load API keys:', error);
        }
    }
    
    renderApiKeys(apiKeys) {
        const container = $('#api-keys-list');
        if (!apiKeys || apiKeys.length === 0) {
            container.html('<div class="text-center py-4 text-xs text-gray-500">No API keys found</div>');
            return;
        }
        
        let html = '';
        apiKeys.forEach(key => {
            const truncatedKey = key.substring(0, 8) + '...' + key.substring(key.length - 8);
            html += `
                <div class="flex items-center justify-between p-2 bg-gray-900 rounded border border-gray-700">
                    <div class="flex items-center gap-2 flex-1">
                        <code class="text-xs text-indigo-400 font-mono">${truncatedKey}</code>
                        <button class="copy-api-key-btn text-gray-400 hover:text-white transition" data-key="${key}" title="Copy">
                            <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"></path>
                            </svg>
                        </button>
                    </div>
                    <button class="delete-api-key-btn text-red-400 hover:text-red-300 transition" data-key="${key}" title="Delete">
                        <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path>
                        </svg>
                    </button>
                </div>
            `;
        });
        container.html(html);
        
        container.find('.copy-api-key-btn').on('click', function() {
            const key = $(this).data('key');
            navigator.clipboard.writeText(key);
            $(this).addClass('text-green-400');
            setTimeout(() => $(this).removeClass('text-green-400'), 1000);
        });
        
        container.find('.delete-api-key-btn').on('click', (e) => {
            const key = $(e.currentTarget).data('key');
            this.deleteApiKey(key);
        });
    }
    
    async generateApiKey() {
        try {
            const response = await fetch('/api/remote/api-keys', { method: 'POST' });
            if (response.ok) {
                const data = await response.json();
                this.showToast('New API key generated: ' + data.api_key.substring(0, 8) + '...', 'success');
                this.loadApiKeys();
            }
        } catch (error) {
            console.error('Failed to generate API key:', error);
            this.showToast('Failed to generate API key', 'error');
        }
    }
    
    async deleteApiKey(key) {
        if (!confirm('Are you sure you want to revoke this API key?')) {
            return;
        }
        
        try {
            const response = await fetch(`/api/remote/api-keys/${key}`, { method: 'DELETE' });
            if (response.ok) {
                this.showToast('API key revoked successfully', 'success');
                this.loadApiKeys();
            } else {
                this.showToast('Failed to revoke API key', 'error');
            }
        } catch (error) {
            console.error('Failed to delete API key:', error);
            this.showToast('Failed to revoke API key', 'error');
        }
    }
    
    updateApiKeysVisibility() {
        if (this.connectionMode === 'server') {
            $('#api-keys-container').removeClass('hidden');
            this.loadApiKeys();
        } else {
            $('#api-keys-container').addClass('hidden');
        }
    }
    
    loadSavedSettings() {
        const savedMode = localStorage.getItem('remote_connection_mode');
        if (savedMode) {
            this.connectionMode = savedMode;
        }
        
        this.updateApiKeysVisibility();
        
        const savedConnectionStatus = localStorage.getItem('remote_connection_status');
        if (savedConnectionStatus === 'connected') {
            if (this.connectionMode === 'client') {
                const savedUrl = localStorage.getItem('remote_server_url');
                const savedUsername = localStorage.getItem('remote_username');
                const savedApiKey = localStorage.getItem('remote_api_key');
                
                if (savedUrl) {
                    this.connectAsClient(savedUrl, savedUsername, savedApiKey);
                }
            } else if (this.connectionMode === 'server') {
                this.startAsServer();
            }
        }
    }
    
    saveConnectionStatus(status) {
        localStorage.setItem('remote_connection_status', status);
    }
    
    showRemoteSettings() {
        $('#remote-settings-modal').removeClass('hidden');
        
        const savedUrl = localStorage.getItem('remote_server_url');
        const savedUsername = localStorage.getItem('remote_username');
        const savedApiKey = localStorage.getItem('remote_api_key');
        const savedMode = localStorage.getItem('remote_connection_mode');
        
        if (savedUrl) {
            $('#remote-server-url').val(savedUrl);
        }
        if (savedUsername) {
            $('#remote-username').val(savedUsername);
        }
        if (savedApiKey) {
            $('#remote-api-key').val(savedApiKey);
        }
        if (savedMode) {
            $('#remote-connection-mode').val(savedMode);
            this.toggleModeFields();
            this.updateConnectButtonText();
            this.updateApiKeysVisibility();
        }
    }
    
    hideRemoteSettings() {
        $('#remote-settings-modal').addClass('hidden');
    }
    
    toggleModeFields() {
        const mode = $('#remote-connection-mode').val();
        const modeDescription = $('#mode-description');
        const clientFields = $('#client-mode-fields');
        const serverInfo = $('#server-mode-info');
        
        if (mode === 'server') {
            clientFields.hide();
            serverInfo.removeClass('hidden');
            modeDescription.html('<span class="text-green-400 font-medium">Server Mode:</span> Host a server to share your local jobs with other users for collaboration. Connected clients can access your analysis sessions.');
        } else {
            clientFields.show();
            serverInfo.addClass('hidden');
            modeDescription.html('<span class="text-blue-400 font-medium">Client Mode:</span> Connect to a remote analysis server to collaborate on shared jobs with other users.');
        }
    }
    
    updateConnectButtonText() {
        const mode = $('#remote-connection-mode').val();
        if (mode === 'server') {
            $('#connect-remote').text('Start Server Mode');
        } else {
            $('#connect-remote').text('Connect');
        }
    }
    
    async connectToRemote() {
        const serverUrl = $('#remote-server-url').val();
        const username = $('#remote-username').val() || this.currentUser;
        const apiKey = $('#remote-api-key').val();
        const mode = $('#remote-connection-mode').val();
        

        localStorage.setItem('remote_server_url', serverUrl);
        localStorage.setItem('remote_username', username);
        localStorage.setItem('remote_api_key', apiKey);
        localStorage.setItem('remote_connection_mode', mode);
        
        this.connectionMode = mode;
        
        if (mode === 'client') {
            if (!serverUrl) {
                this.showToast('Please enter a server URL', 'error');
                return;
            }
            if (!apiKey) {
                this.showToast('API key is required for connection', 'error');
                return;
            }
            await this.connectAsClient(serverUrl, username, apiKey);
        } else {
            await this.startAsServer();
        }
        
        this.hideRemoteSettings();
    }
    
    async connectAsClient(serverUrl, username, apiKey) {

        this.authErrorOccurred = false;
        try {
            let cleanUrl = serverUrl.trim();
            
            cleanUrl = cleanUrl.replace(/\/+$/, '');
            
            if (cleanUrl.includes('http://') && cleanUrl.includes('ws://')) {
                cleanUrl = cleanUrl.replace('ws://', '');
            }
            if (cleanUrl.includes('https://') && cleanUrl.includes('wss://')) {
                cleanUrl = cleanUrl.replace('wss://', '');
            }

         
            if (cleanUrl.includes(':8000') || cleanUrl.includes('127.0.0.1:8000') || cleanUrl.includes('localhost:8000')) {
                this.showToast('Cannot connect to port 8000 - that is the FastAPI backend. Socket.IO runs on port 5000 (the web UI). Please use http://127.0.0.1:5000 or the correct remote server URL.', 'error');
                this.isConnected = false;
                this.updateConnectionStatus(false);
                return;
            }
            
            this.remoteSocket = io(cleanUrl, {
                transports: ['polling']
            });
            
            this.remoteSocket.on('connect', () => {
                this.isConnected = true;
                this.serverConnectedClients = 0;
        
        this.updateRemoteJobsListDebounce = null;
        
        this.reconnectAttempts = 0;
                this.updateConnectionStatus(true);
                this.startLatencyCheck();
                this.showToast('Connected to remote server', 'success');
                
                this.remoteSocket.emit('collaboration_auth', {
                    username: username,
                    api_key: apiKey,
                    mode: 'client'
                });
            });
            
            this.remoteSocket.on('connect_error', (error) => {
                console.error('[Remote] Connection error:', error);
                this.isConnected = false;
                this.updateConnectionStatus(false);
                

                if (this.connectionMode === 'client') {
                    this.scheduleReconnect();
                }
            });
            
            this.remoteSocket.on('disconnect', () => {
                this.isConnected = false;
                this.updateConnectionStatus(false);
                this.saveConnectionStatus('disconnected');
                

          
                if (this.connectionMode === 'client' && !this.authErrorOccurred) {
                    this.scheduleReconnect();
                }
            });
            
            this.remoteSocket.on('auth_success', (data) => {
                this.currentUser = data.user_id;
                this.saveConnectionStatus('connected');
            });
            
            this.remoteSocket.on('auth_failure', (data) => {
                console.error('[Remote] Auth failure');
                this.showToast('Authentication failed', 'error');
            });
            
            this.remoteSocket.on('auth_error', (data) => {
                console.error('[Remote] Auth error:', data);
                this.authErrorOccurred = true;
                this.isConnected = false;
                this.updateConnectionStatus(false);
                this.showToast('Authentication failed: ' + data.error, 'error');
                this.remoteSocket.disconnect();
                
             
                if (this.reconnectTimeout) {
                    clearTimeout(this.reconnectTimeout);
                    this.reconnectTimeout = null;
                }
                this.reconnectAttempts = 0;
            });
            
            this.remoteSocket.on('job_list', (data) => {
                console.log('[Remote] Job list received:', data.jobs?.length, 'jobs');
                this.updateRemoteJobsList(data.jobs);
            });
            
            this.remoteSocket.on('room_users', (data) => {
                this.updateRoomUsersList(data);
            });
            
            this.remoteSocket.on('user_joined', (data) => {
                this.handleUserJoined(data);
            });
            
            this.remoteSocket.on('user_left', (data) => {
                this.handleUserLeft(data);
            });
            
            this.remoteSocket.on('chat_message', (data) => {
                this.handleRemoteChatMessage(data);
            });
            
            this.remoteSocket.on('job_update', (data) => {
                this.handleJobUpdate(data);
            });
            
            this.remoteSocket.on('job_data_response', (data) => {
                this.handleJobDataResponse(data);
            });
            
            this.remoteSocket.on('pong', () => {
                if (this.pingStartTime) {
                    this.latency = Date.now() - this.pingStartTime;
                    this.latencyHistory.push(this.latency);
                    if (this.latencyHistory.length > 10) {
                        this.latencyHistory.shift();
                    }
                    this.updateConnectionQuality();
                    this.pingStartTime = null;
                }
            });
            
            this.startJobSync();
            this.startRoomUsersSync();

        } catch (error) {
            this.showToast('Failed to connect: ' + error.message, 'error');
        }
    }
    
    async startAsServer() {
        this.connectionMode = 'server';
        this.isConnected = true;
        this.updateConnectionStatus(true);
        this.saveConnectionStatus('connected');
        

        try {
            const listResponse = await fetch('/api/remote/api-keys');
            if (listResponse.ok) {
                const listData = await listResponse.json();
                if (listData.count === 0) {
                   
                    const response = await fetch('/api/remote/api-keys', { method: 'POST' });
                    if (response.ok) {
                        const data = await response.json();
                        this.showToast('Server mode activated. API Key: ' + data.api_key, 'success');
                        this.loadApiKeys();
                    } else {
                        this.showToast('Server mode activated (failed to generate API key)', 'warning');
                    }
                } else {
                  
                    this.showToast('Server mode activated', 'success');
                    this.loadApiKeys();
                }
            } else {
                this.showToast('Server mode activated', 'success');
            }
        } catch (error) {
            console.error('Failed to check/generate API key:', error);
            this.showToast('Server mode activated', 'success');
        }
        
        this.startServerStatusPolling();
        
        this.startJobSync();
    }
    
    startServerStatusPolling() {
        if (this.serverStatusInterval) {
            clearInterval(this.serverStatusInterval);
        }
        
        this.serverStatusInterval = setInterval(() => {
            this.fetchServerStatus();
        }, 5000);
        
        this.fetchServerStatus();
    }
    
    stopServerStatusPolling() {
        if (this.serverStatusInterval) {
            clearInterval(this.serverStatusInterval);
            this.serverStatusInterval = null;
        }
    }
    
    startJobSync() {
        if (this.jobSyncInterval) {
            clearInterval(this.jobSyncInterval);
        }
        
        this.jobSyncInterval = setInterval(() => {
            if (this.connectionMode === 'server') {
                this.loadLocalJobsAsRemote();
            } else if (this.connectionMode === 'client' && this.remoteSocket) {
                this.remoteSocket.emit('request_jobs');
            }
        }, 10000);
        
        if (this.connectionMode === 'server') {
            this.loadLocalJobsAsRemote();
        }
    }
    
    stopJobSync() {
        if (this.jobSyncInterval) {
            clearInterval(this.jobSyncInterval);
            this.jobSyncInterval = null;
        }
    }
    
    async fetchServerStatus() {
        try {
            const response = await fetch('/api/remote/server/status');
            if (response.ok) {
                const data = await response.json();
                this.serverConnectedClients = data.total_connected_clients;
                this.updateConnectionStatus(true);
                
                if (this.connectionMode === 'server' && data.room_details) {
                    const allUsers = [];
                    const seenUserIds = new Set();
                    for (const [roomId, roomData] of Object.entries(data.room_details)) {
                        roomData.users.forEach(user => {
                            if (!seenUserIds.has(user.id)) {
                                seenUserIds.add(user.id);
                                allUsers.push({
                                    user_id: user.id,
                                    username: user.username
                                });
                            }
                        });
                    }
                    this.updateConnectedUsersList(allUsers);
                }
            }
        } catch (error) {
            console.error('Error fetching server status:', error);
        }
    }
    
    async loadLocalJobsAsRemote() {
        try {
            const response = await fetch('/api/remote/jobs');
            if (response.ok) {
                const data = await response.json();
                this.updateRemoteJobsList(data.jobs);
            }
        } catch (error) {
            console.error('Error loading local jobs:', error);
        }
    }
    
    disconnectFromRemote() {

        if (this.reconnectTimeout) {
            clearTimeout(this.reconnectTimeout);
            this.reconnectTimeout = null;
        }
        this.reconnectAttempts = 0;

        if (this.remoteSocket) {
            this.remoteSocket.disconnect();
            this.remoteSocket = null;
        }

        this.isConnected = false;
        this.currentRoom = null;
        this.connectedUsers.clear(); 
        this.remoteJobs.clear();
        this.stopServerStatusPolling();
        this.stopJobSync();
        this.stopLatencyCheck();
        this.stopRoomUsersSync();
        this.saveConnectionStatus('disconnected');
        this.updateConnectionStatus(false);
    }
    
    scheduleReconnect() {
        if (this.reconnectAttempts >= this.maxReconnectAttempts) {
            this.reconnectAttempts = 0;
            return;
        }
        
        this.reconnectAttempts++;
        const delay = this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1);
        const maxDelay = 30000; 
        const actualDelay = Math.min(delay, maxDelay);
        
        this.reconnectTimeout = setTimeout(() => {
            const savedUrl = localStorage.getItem('remote_server_url');
            const savedUsername = localStorage.getItem('remote_username');
            const savedApiKey = localStorage.getItem('remote_api_key');
            
            if (savedUrl && this.connectionMode === 'client') {
                this.connectAsClient(savedUrl, savedUsername, savedApiKey);
            }
        }, actualDelay);
    }
    
    startLatencyCheck() {
        if (this.latencyCheckInterval) {
            clearInterval(this.latencyCheckInterval);
        }

        this.latencyCheckInterval = setInterval(() => {
            if (this.isConnected && this.remoteSocket) {
                this.pingStartTime = Date.now();
                this.remoteSocket.emit('ping');
            }
        }, 5000);
    }

    stopLatencyCheck() {
        if (this.latencyCheckInterval) {
            clearInterval(this.latencyCheckInterval);
            this.latencyCheckInterval = null;
        }
        this.latency = 0;
        this.latencyHistory = [];
        this.updateConnectionQuality();
    }

    startRoomUsersSync() {
        if (this.roomUsersSyncInterval) {
            clearInterval(this.roomUsersSyncInterval);
        }

        this.roomUsersSyncInterval = setInterval(() => {
            if (this.isConnected && this.currentRoom && this.remoteSocket) {
                this.syncRoomUsers();
            }
        }, 10000);
    }

    stopRoomUsersSync() {
        if (this.roomUsersSyncInterval) {
            clearInterval(this.roomUsersSyncInterval);
            this.roomUsersSyncInterval = null;
        }
    }

    async syncRoomUsers() {
        if (!this.currentRoom) return;

        try {
            const response = await fetch(`/api/remote/room/${this.currentRoom}/users`);
            if (response.ok) {
                const data = await response.json();
                const users = data.users || [];
                this.connectedUsers.set(this.currentRoom, new Set(users.map(u => u.user_id)));
                this.updateConnectedUsersList(users);
            }
        } catch (error) {
            console.error('[Remote] Error syncing room users:', error);
        }
    }
    
    updateConnectionQuality() {
        const latencyElement = $('#connection-latency');
        const qualityElement = $('#connection-quality');
        
        if (this.latency === 0) {
            latencyElement.text('-- ms');
            qualityElement.text('--');
            return;
        }
        
        latencyElement.text(`${this.latency} ms`);
        
 
        const avgLatency = this.latencyHistory.length > 0 
            ? this.latencyHistory.reduce((a, b) => a + b, 0) / this.latencyHistory.length 
            : this.latency;
        
        let quality, qualityClass;
        if (avgLatency < 50) {
            quality = 'Excellent';
            qualityClass = 'text-green-400';
        } else if (avgLatency < 100) {
            quality = 'Good';
            qualityClass = 'text-blue-400';
        } else if (avgLatency < 200) {
            quality = 'Fair';
            qualityClass = 'text-yellow-400';
        } else {
            quality = 'Poor';
            qualityClass = 'text-red-400';
        }
        
        qualityElement.removeClass('text-green-400 text-blue-400 text-yellow-400 text-red-400').addClass(qualityClass);
        qualityElement.text(quality);
    }
    
    updateConnectedUsersList(users) {
        const container = $('#connected-users-list');
        container.empty();
        
        if (!users || users.length === 0) {
            container.html('<div class="text-center py-4 text-xs text-gray-500">No users connected</div>');
            return;
        }
        
        const seenUserIds = new Set();
        const uniqueUsers = [];
        
        users.forEach(user => {
            if (!seenUserIds.has(user.user_id)) {
                seenUserIds.add(user.user_id);
                uniqueUsers.push(user);
            }
        });
        
        uniqueUsers.forEach(user => {
            const isCurrentUser = user.user_id === this.currentUser;
            const userHtml = `
                <div class="flex items-center gap-2 p-2 bg-gray-800 rounded border border-gray-700 ${isCurrentUser ? 'border-indigo-500' : ''}">
                    <div class="w-8 h-8 rounded-full bg-gradient-to-br from-indigo-500 to-purple-600 flex items-center justify-center text-white text-xs font-bold">
                        ${user.username ? user.username.charAt(0).toUpperCase() : 'U'}
                    </div>
                    <div class="flex-1">
                        <div class="text-sm text-gray-300">${user.username || 'Unknown'}</div>
                        <div class="text-xs text-gray-500">${isCurrentUser ? '(You)' : ''}</div>
                    </div>
                    <div class="w-2 h-2 bg-green-500 rounded-full"></div>
                </div>
            `;
            container.append(userHtml);
        });
    }
    
    handleRemoteMessage(message) {
        switch (message.type) {
            case 'auth_success':
                break;
            case 'auth_failure':
                this.showToast('Authentication failed', 'error');
                break;
            case 'job_list':
                this.updateRemoteJobsList(message.jobs);
                break;
            case 'user_joined':
                this.handleUserJoined(message);
                break;
            case 'user_left':
                this.handleUserLeft(message);
                break;
            case 'chat_message':
                this.handleRemoteChatMessage(message);
                break;
            case 'job_update':
                this.handleJobUpdate(message);
                break;
            default:
        }
    }
    
    handleRoomUsers(data) {
        const { job_id, users } = data;

        this.connectedUsers.set(job_id, new Set(users.map(u => u.user_id)));
        this.updateRemoteJobsList(this.remoteJobs.get('all') || []);

        if (this.currentRoom === job_id) {
            this.updateConnectedUsersList(users);
        }
    }
    
    updateRemoteJobsList(jobs) {
        if (this.updateRemoteJobsListDebounce) {
            clearTimeout(this.updateRemoteJobsListDebounce);
        }

        this.updateRemoteJobsListDebounce = setTimeout(() => {
            const container = $('#remote-jobs-list');
            container.empty();


            if (!jobs || !Array.isArray(jobs)) {
                if (this.connectionMode === 'server') {
                    container.html('<div class="text-center py-4 text-xs text-gray-500">No local jobs available for sharing</div>');
                } else {
                    container.html('<div class="text-center py-4 text-xs text-gray-500">No remote jobs available</div>');
                }
                return;
            }

            this.remoteJobs.set('all', jobs);

            if (jobs.length === 0) {
                if (this.connectionMode === 'server') {
                    container.html('<div class="text-center py-4 text-xs text-gray-500">No local jobs available for sharing</div>');
                } else {
                    container.html('<div class="text-center py-4 text-xs text-gray-500">No remote jobs available</div>');
                }
                return;
            }
            
            jobs.forEach(job => {
                
                const usersCount = job.connected_users || 0;
                const modeLabel = this.connectionMode === 'server' ? 'LOCAL' : 'REMOTE';
                const modeColor = this.connectionMode === 'server' ? 'bg-green-600' : 'bg-blue-600';
                const filename = job.filename || job.file_name || 'Unknown';
                const status = job.status || 'unknown';
                const jobId = job.job_id || job.id || 'unknown';

                const jobHtml = `
                    <div class="job-item p-3 bg-gray-800 rounded-lg border border-gray-700 hover:border-${this.connectionMode === 'server' ? 'green' : 'blue'}-500 transition cursor-pointer mb-2"
                         data-job-id="${jobId}"
                         data-remote="${this.connectionMode !== 'server'}">
                        <div class="flex items-center justify-between mb-1">
                            <span class="text-sm text-gray-300 font-mono truncate">${filename}</span>
                            <span class="px-2 py-1 ${modeColor} text-white rounded text-xs">${modeLabel}</span>
                        </div>
                        <div class="flex items-center justify-between">
                            <div class="text-xs text-gray-500">Status: ${status}</div>
                            <div class="text-xs text-gray-500 flex items-center">
                                <svg class="w-3 h-3 inline mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7 a4 4 0 11-8 0 4 4 0 018 0z"></path>
                                </svg>
                                ${usersCount} user(s)
                            </div>
                        </div>
                    </div>
                `;
                container.append(jobHtml);
            });
            
            if (this.connectionMode === 'client') {
                container.find('.job-item').off('click').on('click', (e) => {
                    const jobId = $(e.currentTarget).data('job-id');
                    this.joinRemoteJob(jobId);
                });
            } else {
                container.find('.job-item').css('cursor', 'not-allowed').attr('title', 'Use Local Analysis Jobs to work with your jobs');
            }
        }, 100);
    }
    
    async joinRemoteJob(jobId) {
        console.log('[Remote] Joining remote job:', jobId, 'mode:', this.connectionMode, 'isConnected:', this.isConnected, 'remoteSocket:', !!this.remoteSocket);
        if (this.connectionMode === 'server') {
            this.loadJobInUI(jobId);
            this.showToast('Loaded local job', 'success');
            return;
        }

        if (!this.isConnected || !this.remoteSocket) {
            console.error('[Remote] Cannot join - not connected', 'isConnected:', this.isConnected, 'remoteSocket:', !!this.remoteSocket);
            this.showToast('Not connected to remote server', 'error');
            return;
        }

        if (this.currentRoom && this.currentRoom !== jobId) {
            this.remoteSocket.emit('leave_room', {
                job_id: this.currentRoom,
                user_id: this.currentUser
            });
            this.connectedUsers.delete(this.currentRoom);
        }

        this.currentRoom = jobId;

        this.remoteSocket.emit('join_room', {
            job_id: jobId,
            user_id: this.currentUser,
            username: this.username || 'Anonymous'
        });

        
        try {
            const response = await fetch(`/api/remote/room/${jobId}/users`);
            if (response.ok) {
                const data = await response.json();
                const users = data.users || [];
                this.connectedUsers.set(jobId, new Set(users.map(u => u.user_id)));
                this.updateConnectedUsersList(users);
            }
        } catch (error) {
            console.error('[Remote] Error fetching room users:', error);
        }

        this.loadJobInUI(jobId);

        this.showToast('Joined remote job', 'success');
    }
    
    loadJobInUI(jobId) {
        if (typeof loadJob === 'function') {
            loadJob(jobId);
        } else {
            console.error('loadJob function not available globally');
            this.showToast('Failed to load job - loadJob function not available', 'error');
        }
    }
    
    leaveRemoteJob() {
        if (!this.currentRoom || !this.isConnected || !this.remoteSocket) return;
        
        this.remoteSocket.emit('leave_room', {
            job_id: this.currentRoom,
            user_id: this.currentUser
        });
        
        this.currentRoom = null;
    }
    
    async handleUserJoined(message) {
        if (!this.connectedUsers.has(message.job_id)) {
            this.connectedUsers.set(message.job_id, new Set());
        }
        this.connectedUsers.get(message.job_id).add(message.user_id);
        this.updateRemoteJobsList(message.available_jobs || []);

      
        if (this.currentRoom === message.job_id) {
            try {
                const response = await fetch(`/api/remote/room/${message.job_id}/users`);
                if (response.ok) {
                    const data = await response.json();
                    this.updateConnectedUsersList(data.users || []);
                }
            } catch (error) {
                console.error('[Remote] Error fetching room users after user joined:', error);
            }
        }

        this.showToast(`${message.username} joined the session`, 'info');
    }
    
    async handleUserLeft(message) {
        if (this.connectedUsers.has(message.job_id)) {
            this.connectedUsers.get(message.job_id).delete(message.user_id);
        }
        this.updateRemoteJobsList(message.available_jobs || []);

      
        if (this.currentRoom === message.job_id) {
            try {
                const response = await fetch(`/api/remote/room/${message.job_id}/users`);
                if (response.ok) {
                    const data = await response.json();
                    this.updateConnectedUsersList(data.users || []);
                }
            } catch (error) {
                console.error('[Remote] Error fetching room users after user left:', error);
            }
        }

        this.showToast(`${message.username} left the session`, 'info');
    }
    
    handleRemoteChatMessage(message) {
        if (window.chatManager) {
            window.chatManager.addRemoteMessage(message);
        }
    }
    
    handleJobUpdate(message) {
        if (this.connectionMode === 'client' && this.remoteSocket) {
            this.remoteSocket.emit('request_jobs');
        } else if (this.connectionMode === 'server') {
            this.loadLocalJobsAsRemote();
        }
    }
    
    handleJobDataResponse(data) {
        if (data.error) {
            this.showToast('Failed to load job data: ' + data.error, 'error');
            return;
        }
        
        this.loadJobInUI(data);
    }
    
    sendChatMessage(message) {
        if (!this.isConnected || !this.currentRoom) {
            return false;
        }
        
        this.remoteSocket.emit('chat_message', {
            job_id: this.currentRoom,
            user_id: this.currentUser,
            message: message
        });
        
        return true;
    }
    
    updateConnectionStatus(connected) {
        const disconnectBtn = $('#disconnect-remote');
        const connectionIndicator = $('#connection-indicator');
        const connectionIndicatorModal = $('#connection-indicator-modal');
        const connectionText = $('#connection-text');
        const connectionDetails = $('#connection-details');
        const connectionStatusText = $('#connection-status-text');
        const connectionStatusDetail = $('#connection-status-detail');
        const latencyElement = $('#connection-latency');
        const qualityElement = $('#connection-quality');
        
        if (connected) {
            disconnectBtn.removeClass('hidden');
            connectionIndicator.removeClass('bg-red-500').addClass('bg-green-500');
            connectionIndicatorModal.removeClass('bg-red-500').addClass('bg-green-500');
        } else {
            disconnectBtn.addClass('hidden');
            connectionIndicator.removeClass('bg-green-500').addClass('bg-red-500');
            connectionIndicatorModal.removeClass('bg-green-500').addClass('bg-red-500');
        }
        
     
        if (this.connectionMode === 'server') {
            latencyElement.parent().addClass('hidden');
        } else {
            latencyElement.parent().removeClass('hidden');
        }
        
       
        if (this.connectionMode === 'server') {
            if (connected && this.serverConnectedClients > 0) {
                connectionStatusText.text(`${this.serverConnectedClients} user(s) connected`);
                connectionStatusText.removeClass('text-gray-300 text-yellow-400').addClass('text-green-400');
                connectionStatusDetail.text('Server is active and accepting connections');
            } else if (connected) {
                connectionStatusText.text('Server Active');
                connectionStatusText.removeClass('text-gray-300 text-yellow-400').addClass('text-green-400');
                connectionStatusDetail.text('Server is running and waiting for connections');
            } else {
                connectionStatusText.text('Server Inactive');
                connectionStatusText.removeClass('text-green-400 text-yellow-400').addClass('text-gray-300');
                connectionStatusDetail.text('Server mode is not active');
            }
        } else {
            if (connected) {
                connectionStatusText.text('Connected');
                connectionStatusText.removeClass('text-gray-300 text-yellow-400').addClass('text-green-400');
                connectionStatusDetail.text('Successfully connected to remote server');
            } else {
                connectionStatusText.text('Disconnected');
                connectionStatusText.removeClass('text-green-400 text-yellow-400').addClass('text-gray-300');
                connectionStatusDetail.text('No active remote connection');
            }
        }
        
        if (this.connectionMode === 'server') {
            if (connected && this.serverConnectedClients > 0) {
                connectionText.text(`${this.serverConnectedClients} user(s) connected`);
                connectionText.removeClass('text-gray-300 text-yellow-400').addClass('text-green-400');
                connectionDetails.text('Server is active and accepting connections');
            } else if (connected) {
                connectionText.text('Server Active');
                connectionText.removeClass('text-gray-300 text-yellow-400').addClass('text-green-400');
                connectionDetails.text('Server is running and waiting for connections');
            } else {
                connectionText.text('Server Inactive');
                connectionText.removeClass('text-green-400 text-yellow-400').addClass('text-gray-300');
                connectionDetails.text('Server mode is not active');
            }
        } else {
            if (connected) {
                connectionText.text('Connected');
                connectionText.removeClass('text-gray-300 text-yellow-400').addClass('text-green-400');
                connectionDetails.text('Successfully connected to remote server');
            } else {
                connectionText.text('Disconnected');
                connectionText.removeClass('text-green-400 text-yellow-400').addClass('text-gray-300');
                connectionDetails.text('No active remote connection');
            }
        }
    }
    
    showToast(message, type = 'info') {
        const toast = $(`
            <div class="px-4 py-3 rounded-lg shadow-lg flex items-center gap-2 animate-slide-in ${
                type === 'success' ? 'bg-green-600' :
                type === 'error' ? 'bg-red-600' :
                type === 'warning' ? 'bg-yellow-600' :
                'bg-blue-600'
            } text-white">
                ${message}
            </div>
        `);
        
        $('#toast-container').append(toast);
        
        setTimeout(() => {
            toast.fadeOut(300, () => toast.remove());
        }, 3000);
    }
}

$(document).ready(() => {
    window.remoteCollaborationManager = new RemoteCollaborationManager();
});
