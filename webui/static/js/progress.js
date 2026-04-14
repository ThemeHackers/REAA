$(document).ready(function() {
    let currentJobId = null;
    let progressInterval = null;
    function initProgress(jobId) {
        currentJobId = jobId;
        startProgressPolling(jobId);
    }
    function startProgressPolling(jobId) {
        if (progressInterval) {
            clearInterval(progressInterval);
        }

        progressInterval = setInterval(() => {
            pollProgress(jobId);
        }, 2000);
    }
    function pollProgress(jobId) {
        $.get(`/api/jobs/${jobId}/status`, function(data) {
            updateProgressUI(data);
        }).fail(function(xhr) {
            console.error('Failed to poll progress:', xhr);
        });
    }
    function updateProgressUI(data) {
        const progressContainer = $('#progress-container');
        if (progressContainer.length === 0) return;

        const progress = data.progress || 0;
        const status = data.status || 'unknown';
        const message = data.message || '';
        const progressBar = $('#progress-bar');
        if (progressBar.length > 0) {
            progressBar.css('width', `${progress}%`);
            progressBar.attr('aria-valuenow', progress);
        }
        const progressText = $('#progress-text');
        if (progressText.length > 0) {
            progressText.text(`${progress}%`);
        }
        const statusText = $('#status-text');
        if (statusText.length > 0) {
            statusText.text(status);
        }
        const messageText = $('#message-text');
        if (messageText.length > 0) {
            messageText.text(message);
        }
        if (status === 'completed' || status === 'failed') {
            stopProgressPolling();
        }
    }
    function stopProgressPolling() {
        if (progressInterval) {
            clearInterval(progressInterval);
            progressInterval = null;
        }
    }
    window.progressManager = {
        initProgress: initProgress,
        startProgressPolling: startProgressPolling,
        stopProgressPolling: stopProgressPolling,
        pollProgress: pollProgress
    };
});
