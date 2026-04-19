import os
import json
import logging
import structlog
from typing import Optional, Dict, Any, List, Callable, TYPE_CHECKING
from pathlib import Path

from core.config import settings

if TYPE_CHECKING:
    import frida
    from frida.core import Session

try:
    import frida
    from frida.core import Session
    FRIDA_AVAILABLE = True
except ImportError:
    FRIDA_AVAILABLE = False

log = structlog.get_logger()


class FridaInstrumentation:
    """wrapper for Frida dynamic instrumentation"""

    def __init__(self):
        self.device = None
        self.session = None
        self.scripts: List[Any] = []
        self.messages: List[Dict[str, Any]] = []
        self.auto_reconnect = True
        self.max_reconnect_attempts = 3
        self.reconnect_delay = 2

        if not FRIDA_AVAILABLE:
            log.warning("Frida not available, instrumentation will be disabled")
            return

        try:
            self.device = frida.get_local_device()
            log.info("Frida initialized successfully")
        except Exception as e:
            log.error(f"Failed to initialize Frida: {e}", exc_info=True)
            self._attempt_reconnect()

    def attach_to_process(self, process_name: str) -> bool:
        if not FRIDA_AVAILABLE or not self.device:
            return False

        try:
            self.session = self.device.attach(process_name)
            self.session.on('message', self._on_message)
            log.info(f"Attached to process: {process_name}")
            return True
        except Exception as e:
            log.error(f"Failed to attach to process {process_name}: {e}", exc_info=True)
            return False

    def attach_to_pid(self, pid: int) -> bool:
        if not FRIDA_AVAILABLE or not self.device:
            return False

        try:
            self.session = self.device.attach(pid)
            self.session.on('message', self._on_message)
            log.info(f"Attached to PID: {pid}")
            return True
        except Exception as e:
            log.error(f"Failed to attach to PID {pid}: {e}", exc_info=True)
            return False

    def spawn_process(self, binary_path: str, args: List[str] = None) -> bool:
        if not FRIDA_AVAILABLE or not self.device:
            return False

        try:
            cmd = [binary_path]
            if args:
                cmd.extend(args)

            pid = self.device.spawn(cmd)
            self.session = self.device.attach(pid)
            self.device.resume(pid)
            log.info(f"Spawned and attached to process: {binary_path} (PID: {pid})")
            return True
        except Exception as e:
            log.error(f"Failed to spawn process {binary_path}: {e}", exc_info=True)
            return False

    def load_script(self, script_content: str) -> Optional[Any]:
        if not self.session:
            log.error("No active session, cannot load script")
            return None

        try:
            script = self.session.create_script(script_content)
            script.on('message', self._on_message)
            script.load()
            self.scripts.append(script)
            log.info("Frida script loaded successfully")
            return script
        except Exception as e:
            log.error(f"Failed to load Frida script: {e}", exc_info=True)
            return None

    def load_script_file(self, script_path: str) -> Optional[Any]:
        script_file = Path(script_path)
        if not script_file.exists():
            log.error(f"Script file not found: {script_path}")
            return None

        try:
            script_content = script_file.read_text(encoding='utf-8')
            return self.load_script(script_content)
        except Exception as e:
            log.error(f"Failed to read script file {script_path}: {e}", exc_info=True)
            return None

    def unload_script(self, script: Any) -> bool:
        try:
            script.unload()
            self.scripts.remove(script)
            log.info("Frida script unloaded successfully")
            return True
        except Exception as e:
            log.error(f"Failed to unload Frida script: {e}", exc_info=True)
            return False

    def unload_all_scripts(self) -> bool:
        success = True
        for script in self.scripts[:]:
            if not self.unload_script(script):
                success = False
        return success

    def detach(self) -> bool:
        if not self.session:
            return True

        try:
            self.unload_all_scripts()
            self.session.detach()
            self.session = None
            log.info("Detached from process")
            return True
        except Exception as e:
            log.error(f"Failed to detach: {e}", exc_info=True)
            return False

    def get_messages(self) -> List[Dict[str, Any]]:
        messages = self.messages.copy()
        self.messages.clear()
        return messages

    def _on_message(self, message: Dict[str, Any], data: Any):
        self.messages.append({
            "message": message,
            "data": data,
            "timestamp": str(os.times())
        })

        if message.get('type') == 'send':
            log.info(f"Frida message: {message.get('payload')}")
        elif message.get('type') == 'error':
            log.error(f"Frida error: {message.get('stack')}")

    def is_available(self) -> bool:
        return FRIDA_AVAILABLE and self.device is not None

    def _attempt_reconnect(self) -> bool:
        """Attempt to reconnect to Frida device"""
        if not self.auto_reconnect:
            return False

        for attempt in range(self.max_reconnect_attempts):
            try:
                import time
                time.sleep(self.reconnect_delay)
                self.device = frida.get_local_device()
                log.info(f"Successfully reconnected to Frida device (attempt {attempt + 1})")
                return True
            except Exception as e:
                log.warning(f"Reconnect attempt {attempt + 1} failed: {e}")
        
        log.error("Failed to reconnect to Frida device after all attempts")
        return False


class FridaScriptTemplates:
    """Pre-defined Frida instrumentation scripts"""

    @staticmethod
    def api_call_tracing() -> str:
        return """
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
        """

    @staticmethod
    def memory_allocation_tracking() -> str:
        return """
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
        """

    @staticmethod
    def file_operation_monitoring() -> str:
        return """
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
        """

    @staticmethod
    def network_connection_monitoring() -> str:
        return """
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
        """

    @staticmethod
    def crypto_monitoring() -> str:
        return """
        var crypto_ops = [];

        function log_crypto_op(op, algo, key_size) {
            var op_info = {
                operation: op,
                algorithm: algo,
                key_size: key_size,
                timestamp: Date.now()
            };
            send(op_info);
        }

        // Monitor common crypto APIs
        Interceptor.attach(Module.findExportByName(null, "CryptEncrypt"), {
            onEnter: function(args) {
                log_crypto_op("CryptEncrypt", "AES/DES", args[3].toInt32());
            }
        });

        Interceptor.attach(Module.findExportByName(null, "CryptDecrypt"), {
            onEnter: function(args) {
                log_crypto_op("CryptDecrypt", "AES/DES", args[3].toInt32());
            }
        });

        Interceptor.attach(Module.findExportByName(null, "CryptCreateHash"), {
            onEnter: function(args) {
                log_crypto_op("CryptCreateHash", "HASH", 0);
            }
        });

        // Monitor OpenSSL
        var openssl_encrypt = Module.findExportByName(null, "EVP_EncryptInit_ex");
        if (openssl_encrypt) {
            Interceptor.attach(openssl_encrypt, {
                onEnter: function(args) {
                    log_crypto_op("EVP_EncryptInit_ex", "OpenSSL", 0);
                }
            });
        }
        """

    @staticmethod
    def registry_monitoring() -> str:
        return """
        var registry_ops = [];

        function log_reg_op(op, key, value) {
            var op_info = {
                operation: op,
                key: key ? key.readCString() : "null",
                value: value ? value.readCString() : "null",
                timestamp: Date.now()
            };
            send(op_info);
        }

        Interceptor.attach(Module.findExportByName(null, "RegOpenKeyExA"), {
            onEnter: function(args) {
                this.key = args[1];
            },
            onLeave: function(retval) {
                if (retval.toInt32() === 0) {
                    log_reg_op("RegOpenKeyExA", this.key, null);
                }
            }
        });

        Interceptor.attach(Module.findExportByName(null, "RegSetValueExA"), {
            onEnter: function(args) {
                this.key = args[0];
                this.value = args[2];
            },
            onLeave: function(retval) {
                if (retval.toInt32() === 0) {
                    log_reg_op("RegSetValueExA", this.key, this.value);
                }
            }
        });

        Interceptor.attach(Module.findExportByName(null, "RegQueryValueExA"), {
            onEnter: function(args) {
                this.key = args[0];
            },
            onLeave: function(retval) {
                if (retval.toInt32() === 0) {
                    log_reg_op("RegQueryValueExA", this.key, null);
                }
            }
        });
        """


_frida_instance: Optional[FridaInstrumentation] = None


def get_frida() -> FridaInstrumentation:
    global _frida_instance
    if _frida_instance is None:
        _frida_instance = FridaInstrumentation()
    return _frida_instance
