var allocations = [];

Interceptor.attach(Module.findExportByName(null, "malloc"), {
    onEnter: function(args) {
        this.size = args[0].toInt32();
    },
    onLeave: function(retval) {
        if (retval.toInt32() !== 0) {
            var alloc_info = {
                type: "malloc",
                size: this.size,
                address: retval.toString(),
                backtrace: Thread.backtrace(this.context, Backtracer.ACCURATE)
                    .map(DebugSymbol.fromAddress)
                    .filter(function(sym) { return sym !== null; })
                    .map(function(sym) { return sym.name; })
            };
            send(alloc_info);
        }
    }
});

Interceptor.attach(Module.findExportByName(null, "free"), {
    onEnter: function(args) {
        var free_info = {
            type: "free",
            address: args[0].toString(),
            backtrace: Thread.backtrace(this.context, Backtracer.ACCURATE)
                .map(DebugSymbol.fromAddress)
                .filter(function(sym) { return sym !== null; })
                .map(function(sym) { return sym.name; })
        };
        send(free_info);
    }
});

send({type: "status", message: "Memory tracking script loaded"});
