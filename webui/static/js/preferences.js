$(document).ready(function() {
    const DEFAULT_PREFERENCES = {
        memoryLayout: {
            showHexViewer: true,
            hexBytesPerLine: 16,
            showMemoryMap: true,
            showStackHeap: true,
            autoScroll: false
        },
        ui: {
            theme: 'dark',
            sidebarCollapsed: false,
            modalsRememberPosition: true,
            keyboardShortcuts: true
        }
    };

    let userPreferences = {};

    function loadPreferences() {
        const saved = localStorage.getItem('user_preferences');
        if (saved) {
            try {
                userPreferences = JSON.parse(saved);
                userPreferences = mergeWithDefaults(userPreferences);
            } catch (e) {
                console.error('Failed to load preferences:', e);
                userPreferences = JSON.parse(JSON.stringify(DEFAULT_PREFERENCES));
            }
        } else {
            userPreferences = JSON.parse(JSON.stringify(DEFAULT_PREFERENCES));
        }
        applyPreferences();
    }

    function mergeWithDefaults(saved) {
        const merged = JSON.parse(JSON.stringify(DEFAULT_PREFERENCES));
        
        function deepMerge(target, source) {
            for (const key in source) {
                if (source[key] instanceof Object && key in target) {
                    deepMerge(target[key], source[key]);
                } else {
                    target[key] = source[key];
                }
            }
        }
        
        deepMerge(merged, saved);
        return merged;
    }

    function savePreferences() {
        localStorage.setItem('user_preferences', JSON.stringify(userPreferences));
    }

    function getPreference(path) {
        const keys = path.split('.');
        let value = userPreferences;
        for (const key of keys) {
            value = value?.[key];
        }
        return value;
    }

    function setPreference(path, value) {
        const keys = path.split('.');
        let obj = userPreferences;
        for (let i = 0; i < keys.length - 1; i++) {
            if (!(keys[i] in obj)) {
                obj[keys[i]] = {};
            }
            obj = obj[keys[i]];
        }
        obj[keys[keys.length - 1]] = value;
        savePreferences();
    }

    function applyPreferences() {
      
        if (userPreferences.ui.theme === 'light') {
            document.body.classList.add('light-theme');
        }
        
        if (userPreferences.ui.sidebarCollapsed) {
            $('.sidebar').addClass('collapsed');
        }

        applyMemoryPreferences();
    }

    function applyMemoryPreferences() {
        const prefs = userPreferences.memoryLayout;
        
        if (!prefs.showHexViewer) {
            $('.hex-viewer').addClass('hidden');
        }
    }

    function setupPreferenceListeners() {
        $('#hex-toggle').on('click', function() {
            const show = !$('.hex-viewer').hasClass('hidden');
            setPreference('memoryLayout.showHexViewer', !show);
            $('.hex-viewer').toggleClass('hidden');
        });

        $('#theme-toggle').on('click', function() {
            const currentTheme = getPreference('ui.theme');
            const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
            setPreference('ui.theme', newTheme);
            document.body.classList.toggle('light-theme');
        });
    }

    function resetPreferences() {
        if (confirm('Are you sure you want to reset all preferences to defaults?')) {
            localStorage.removeItem('user_preferences');
            loadPreferences();
            showToast('Preferences reset to defaults', 'success');
        }
    }

    function exportPreferences() {
        const prefs = JSON.stringify(userPreferences, null, 2);
        const blob = new Blob([prefs], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        
        const link = document.createElement('a');
        link.href = url;
        link.download = 'preferences.json';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
    }

    function importPreferences(file) {
        const reader = new FileReader();
        reader.onload = function(e) {
            try {
                const imported = JSON.parse(e.target.result);
                userPreferences = mergeWithDefaults(imported);
                savePreferences();
                applyPreferences();
                showToast('Preferences imported successfully', 'success');
            } catch (err) {
                showToast('Failed to import preferences', 'error');
            }
        };
        reader.readAsText(file);
    }

    loadPreferences();
    setupPreferenceListeners();

    window.preferencesManager = {
        get: getPreference,
        set: setPreference,
        reset: resetPreferences,
        export: exportPreferences,
        import: importPreferences,
        load: loadPreferences,
        save: savePreferences
    };
});
