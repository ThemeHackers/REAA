self.onmessage = function(e) {
    const { type, data } = e.data;
    
    if (type === 'search') {
        performHexSearch(data);
    } else if (type === 'searchBytes') {
        performByteSearch(data);
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
    } else if (searchType === 'regex') {
       
        try {
            const regex = new RegExp(pattern, 'gi');
            const str = String.fromCharCode(...bytes);
            let match;
            while ((match = regex.exec(str)) !== null) {
                results.push(match.index);
            }
        } catch (e) {
            self.postMessage({ type: 'error', message: 'Invalid regex pattern' });
            return;
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

function performByteSearch({ bytes, searchBytes }) {
    const results = [];
    const startTime = performance.now();
    
    if (!bytes || !searchBytes || searchBytes.length === 0) {
        self.postMessage({ type: 'searchResult', results: [], duration: 0 });
        return;
    }
    
    for (let i = 0; i <= bytes.length - searchBytes.length; i++) {
        let match = true;
        for (let j = 0; j < searchBytes.length; j++) {
            if (bytes[i + j] !== searchBytes[j]) {
                match = false;
                break;
            }
        }
        if (match) {
            results.push(i);
        }
    }
    
    const duration = performance.now() - startTime;
    self.postMessage({ type: 'searchResult', results, duration });
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
