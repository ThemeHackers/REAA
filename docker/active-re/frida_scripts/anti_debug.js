var anti_debug_detected = false;

function check_debugger() {
    var checks = {
        is_debugger_present: false,
        ptrace_antidebug: false,
        timing_check: false
    };

    try {
        Process.enumerateModules().forEach(function(module) {
            if (module.name === "frida-agent" || module.name === "frida") {
                checks.is_debugger_present = true;
            }
        });
    } catch (e) {}

    try {
        var ptrace = Module.findExportByName(null, "ptrace");
        if (ptrace) {
            Interceptor.attach(ptrace, {
                onEnter: function(args) {
                    checks.ptrace_antidebug = true;
                }
            });
        }
    } catch (e) {}

    try {
        var start = Date.now();
        for (var i = 0; i < 1000000; i++) {}
        var end = Date.now();
        if (end - start > 100) {
            checks.timing_check = true;
        }
    } catch (e) {}

    if (checks.is_debugger_present || checks.ptrace_antidebug || checks.timing_check) {
        anti_debug_detected = true;
        send({
            type: "anti_debug",
            detected: true,
            checks: checks
        });
    }
}

setInterval(check_debugger, 5000);

send({type: "status", message: "Anti-debug detection script loaded"});
