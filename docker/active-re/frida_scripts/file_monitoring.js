var file_ops = [];

function log_file_op(op, path, handle) {
    var op_info = {
        operation: op,
        path: path ? path.readCString() : "null",
        handle: handle ? handle.toString() : "null",
        timestamp: Date.now()
    };
    send(op_info);
}

Interceptor.attach(Module.findExportByName(null, "CreateFileA"), {
    onEnter: function(args) {
        this.path = args[0];
    },
    onLeave: function(retval) {
        log_file_op("CreateFileA", this.path, retval);
    }
});

Interceptor.attach(Module.findExportByName(null, "CreateFileW"), {
    onEnter: function(args) {
        this.path = args[0];
    },
    onLeave: function(retval) {
        log_file_op("CreateFileW", this.path, retval);
    }
});

Interceptor.attach(Module.findExportByName(null, "ReadFile"), {
    onEnter: function(args) {
        this.handle = args[0];
    },
    onLeave: function(retval) {
        log_file_op("ReadFile", null, this.handle);
    }
});

Interceptor.attach(Module.findExportByName(null, "WriteFile"), {
    onEnter: function(args) {
        this.handle = args[0];
    },
    onLeave: function(retval) {
        log_file_op("WriteFile", null, this.handle);
    }
});

send({type: "status", message: "File monitoring script loaded"});
