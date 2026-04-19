var api_calls = [];

function log_api_call(api_name, args) {
    var call_info = {
        api: api_name,
        args: args.map(function(arg) {
            try {
                return arg.toString();
            } catch (e) {
                return "[object]";
            }
        }),
        backtrace: Thread.backtrace(this.context, Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress)
            .filter(function(sym) { return sym !== null; })
            .map(function(sym) { return sym.name; })
    };
    send(call_info);
}

var common_apis = [
    "CreateFileA", "CreateFileW",
    "ReadFile", "WriteFile",
    "RegOpenKeyExA", "RegOpenKeyExW",
    "InternetConnectA", "InternetConnectW",
    "socket", "connect", "send", "recv"
];

common_apis.forEach(function(api_name) {
    var api_ptr = Module.findExportByName(null, api_name);
    if (api_ptr !== null) {
        Interceptor.attach(api_ptr, {
            onEnter: function(args) {
                log_api_call(api_name, args);
            }
        });
    }
});

send({type: "status", message: "API tracing script loaded"});
