var network_ops = [];

function log_network_op(op, args) {
    var op_info = {
        operation: op,
        args: [],
        timestamp: Date.now()
    };

    if (op === "connect") {
        var sockaddr = args[1];
        var family = sockaddr.readU16();
        if (family === 2) {
            var port = sockaddr.add(2).readU16();
            var ip = sockaddr.add(4).readU32();
            op_info.address = [
                ip & 0xff,
                (ip >> 8) & 0xff,
                (ip >> 16) & 0xff,
                (ip >> 24) & 0xff
            ].join('.');
            op_info.port = port;
        }
    }

    send(op_info);
}

Interceptor.attach(Module.findExportByName(null, "socket"), {
    onLeave: function(retval) {
        log_network_op("socket", [retval]);
    }
});

Interceptor.attach(Module.findExportByName(null, "connect"), {
    onEnter: function(args) {
        log_network_op("connect", args);
    }
});

Interceptor.attach(Module.findExportByName(null, "send"), {
    onEnter: function(args) {
        this.sock = args[0];
        this.len = args[2].toInt32();
    },
    onLeave: function(retval) {
        log_network_op("send", [this.sock, this.len, retval]);
    }
});

Interceptor.attach(Module.findExportByName(null, "recv"), {
    onEnter: function(args) {
        this.sock = args[0];
        this.len = args[2].toInt32();
    },
    onLeave: function(retval) {
        log_network_op("recv", [this.sock, this.len, retval]);
    }
});

send({type: "status", message: "Network monitoring script loaded"});
