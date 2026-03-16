'use strict';

/**
 * Unified Root/Tamper Detection Trigger Script
 * - Works with BOTH native-only and Java-available processes.
 * - Unifies all terminate/exit/kill/abort style signals into ONE event:
 *     ROOT_DETECTION_TRIGGERED
 * - Optional: keyword string tracing for "root/jailbreak" (Java layer).
 *
 * Usage:
 *   frida -U -f <pkg> -l this.js --no-pause
 *   objection -g <pkg> explore --startup-script this.js
 */

function now() { return Date.now(); }

// =========================
// Global config
// =========================
const KEYWORDS = ['root', 'jailbroken', 'jailbreak']; // adjust if needed
const KEYWORD_RE = /(security|root|tamper|jailbreak|magisk|frida|hook|emulator|debug)/i;

// Rate limit for string hits (Java)
const PRINT_MAX_PER_SEC = 10;
const DEDUP_MS = 10_000;

// =========================
// Unified trigger state
// =========================
const RootDetect = {
  triggered: false,
  firstTag: null,
  firstDetail: null,
  firstStack: null,
  firstTime: 0
};

function emit(obj) {
  try { send(obj); } catch (e) { /* ignore */ }
}

function nativeBacktrace(context) {
  try {
    return Thread.backtrace(context, Backtracer.ACCURATE)
      .map(DebugSymbol.fromAddress)
      .join("\n");
  } catch (e) {
    return "(native backtrace unavailable)";
  }
}

function javaStacktraceSafe() {
  try {
    const Exception = Java.use('java.lang.Exception');
    const Log = Java.use('android.util.Log');
    return Log.getStackTraceString(Exception.$new());
  } catch (e) {
    return "(java stack unavailable)";
  }
}

/**
 * THE ONLY place to declare "detection worked".
 * Any exit/kill/abort/etc funnels into this.
 */
function triggerRootDetection(tag, detail, nativeCtx /* may be null */, javaCtx /* may be null */) {
  if (RootDetect.triggered) return;

  RootDetect.triggered = true;
  RootDetect.firstTag = tag;
  RootDetect.firstDetail = (detail === null || detail === undefined) ? "" : String(detail);
  RootDetect.firstTime = Date.now();

  // prefer native backtrace if available
  if (nativeCtx) {
    RootDetect.firstStack = nativeBacktrace(nativeCtx);
  } else if (javaCtx && Java.available) {
    RootDetect.firstStack = javaStacktraceSafe();
  } else {
    RootDetect.firstStack = "(no stack context)";
  }

  const msg = "🚨 Rooting detection mechanism WORKED!";
  console.log("\n==============================");
  console.log(msg);
  console.log("Trigger :", RootDetect.firstTag);
  console.log("Detail  :", RootDetect.firstDetail);
  console.log("Stack   :\n" + RootDetect.firstStack);
  console.log("==============================\n");

  emit({
    event: "ROOT_DETECTION_TRIGGERED",
    tag: RootDetect.firstTag,
    detail: RootDetect.firstDetail,
    time: RootDetect.firstTime,
  });
}

// =========================
// Native terminate watchers (NO Java required)
// =========================
function hookIfExists(name, onEnter) {
  const addr = Module.findExportByName(null, name);
  if (!addr) return false;
  console.log(`[+] Hooking ${name} @ ${addr}`);
  Interceptor.attach(addr, { onEnter });
  return true;
}

function hookTerminateNative(name, formatter) {
  return hookIfExists(name, function (args) {
    const detail = formatter ? formatter.call(this, args) : "";
    triggerRootDetection(`native:${name}`, detail, this.context, null);
  });
}

// Native termination-related APIs
hookTerminateNative("exit", function (args) { return `code=${args[0].toInt32()}`; });
hookTerminateNative("_exit", function (args) { return `code=${args[0].toInt32()}`; });
hookTerminateNative("abort", function () { return ""; });
hookTerminateNative("raise", function (args) { return `sig=${args[0].toInt32()}`; });
hookTerminateNative("kill", function (args) {
  return `pid=${args[0].toInt32()} sig=${args[1].toInt32()}`;
});
hookTerminateNative("tgkill", function (args) {
  return `tgid=${args[0].toInt32()} tid=${args[1].toInt32()} sig=${args[2].toInt32()}`;
});
hookTerminateNative("__android_log_assert", function (args) {
  try {
    const tag = args[0].readCString();
    const cond = args[1].readCString();
    const msg = args[2].readCString();
    return `tag=${tag} cond=${cond} msg=${msg}`;
  } catch (e) {
    return `parse error: ${e}`;
  }
});

// Optional: if you want to treat libc "pthread_kill" / "sigqueue" as triggers too
hookTerminateNative("pthread_kill", function (args) {
  try { return `thread=${args[0]} sig=${args[1].toInt32()}`; } catch (e) { return ""; }
});
hookTerminateNative("sigqueue", function (args) {
  try { return `pid=${args[0].toInt32()} sig=${args[1].toInt32()}`; } catch (e) { return ""; }
});

// =========================
// Java-based keyword tracing + UI watchers + Java exit watchers
// (only if Java is available)
// =========================
if (!Java.available) {
  console.log("[!] Java not available. Native terminate watchers are active.");
  console.log("[+] Unified RootDetect trigger loaded (native-only).");
  // Done.
} else {
  // -------------------------
  // Java keyword tracing (strings)
  // -------------------------
  const seen = new Map();
  let printedInWindow = 0;
  let windowStart = now();

  function shouldPrint(s) {
    const t = now();
    if (t - windowStart > 1000) {
      windowStart = t;
      printedInWindow = 0;
    }
    if (printedInWindow >= PRINT_MAX_PER_SEC) return false;

    const last = seen.get(s);
    if (last && (t - last) < DEDUP_MS) return false;

    seen.set(s, t);
    printedInWindow++;
    return true;
  }

  function containsKeyword(s) {
    if (!s) return false;
    const low = ('' + s).toLowerCase();
    for (let i = 0; i < KEYWORDS.length; i++) {
      if (low.indexOf(KEYWORDS[i]) !== -1) return true;
    }
    return false;
  }

  function traceIfMatch(s, origin) {
    try {
      if (!containsKeyword(s)) return;
      if (!shouldPrint('' + s)) return;

      const stack = javaStacktraceSafe();
      console.log('\n========== [String Trace HIT] ==========');
      console.log('Origin : ' + origin);
      console.log('Value  : ' + s);
      console.log('Stack  :\n' + stack);
      console.log('=======================================\n');

      emit({ event: "keyword_hit", origin, value: String(s) });
    } catch (e) {
      // ignore
    }
  }

  function safeString(obj) {
    try {
      if (obj === null || obj === undefined) return "";
      return obj.toString();
    } catch (e) {
      return "";
    }
  }

  function hit(tag, text) {
    const s = (text === null || text === undefined) ? "" : String(text);
    if (KEYWORD_RE.test(s)) {
      console.log(`[HIT][${tag}] ${s}`);
      emit({ event: "keyword_hit", tag, text: s });
    }
  }

  // -------------------------
  // Java hooks
  // -------------------------
  Java.perform(function () {
    console.log("[+] Java is available. Installing Java hooks...");

    const StringCls = Java.use('java.lang.String');
    const StringBuilder = Java.use('java.lang.StringBuilder');

    // ---- String constructors (common sources of messages) ----
    StringCls.$init.overload('java.lang.String').implementation = function (s) {
      const ret = this.$init(s);
      traceIfMatch(s, 'String.<init>(String)');
      return ret;
    };

    StringCls.$init.overload('[B').implementation = function (bytes) {
      const ret = this.$init(bytes);
      traceIfMatch(this.toString(), 'String.<init>(byte[])');
      return ret;
    };

    // Some builds have (byte[], String charset)
    try {
      StringCls.$init.overload('[B', 'java.lang.String').implementation = function (bytes, cs) {
        const ret = this.$init(bytes, cs);
        traceIfMatch(this.toString(), 'String.<init>(byte[], charset)');
        return ret;
      };
    } catch (e) {}

    StringCls.$init.overload('[C').implementation = function (chars) {
      const ret = this.$init(chars);
      traceIfMatch(this.toString(), 'String.<init>(char[])');
      return ret;
    };

    // ---- StringBuilder.toString ----
    StringBuilder.toString.implementation = function () {
      const s = this.toString.call(this);
      traceIfMatch(s, 'StringBuilder.toString()');
      return s;
    };

    // (Optional) StringBuffer
    try {
      const StringBuffer = Java.use('java.lang.StringBuffer');
      StringBuffer.toString.implementation = function () {
        const s = this.toString.call(this);
        traceIfMatch(s, 'StringBuffer.toString()');
        return s;
      };
    } catch (e) {}

    console.log('[+] String keyword trace hooks installed. keywords=' + KEYWORDS.join(', '));

    // -------------------------
    // UI watchers (keyword-only)
    // -------------------------
    // Toast
    try {
      const Toast = Java.use('android.widget.Toast');
      Toast.makeText.overload('android.content.Context', 'java.lang.CharSequence', 'int').implementation =
        function (ctx, text, duration) {
          hit("Toast.makeText", safeString(text));
          return Toast.makeText.overload('android.content.Context', 'java.lang.CharSequence', 'int')
            .call(this, ctx, text, duration);
        };
    } catch (e) {}

    // AlertDialog.Builder
    try {
      const Builder = Java.use('android.app.AlertDialog$Builder');
      Builder.setMessage.overload('java.lang.CharSequence').implementation = function (msg) {
        hit("AlertDialog.setMessage", safeString(msg));
        return Builder.setMessage.overload('java.lang.CharSequence').call(this, msg);
      };
      Builder.setTitle.overload('java.lang.CharSequence').implementation = function (title) {
        hit("AlertDialog.setTitle", safeString(title));
        return Builder.setTitle.overload('java.lang.CharSequence').call(this, title);
      };
    } catch (e) {}

    // TextView.setText (keyword-only)
    try {
      const TextView = Java.use('android.widget.TextView');
      TextView.setText.overload('java.lang.CharSequence').implementation = function (text) {
        const s = safeString(text);
        if (KEYWORD_RE.test(s)) hit("TextView.setText", s);
        return TextView.setText.overload('java.lang.CharSequence').call(this, text);
      };
    } catch (e) {}
    try {
      const Toast = Java.use('android.widget.Toast');
    
      // 1) Toast.makeText(...) 
      Toast.makeText.overload('android.content.Context', 'java.lang.CharSequence', 'int')
        .implementation = function (ctx, text, duration) {
          const msg = safeString(text);          // CharSequence -> String
          if (KEYWORD_RE.test(msg)) {
            hit("Toast.makeText", msg);          
          }
          return Toast.makeText.overload('android.content.Context', 'java.lang.CharSequence', 'int')
            .call(this, ctx, text, duration);
        };
    
      // 2) Toast.show()
      Toast.show.implementation = function () {
        try {
          const v = this.getView();
          if (v) {
            // android.R.id.message = 16908299
            const tv = v.findViewById(16908299);
            if (tv) {
              const msg = safeString(tv.getText());
              if (KEYWORD_RE.test(msg)) {
                hit("Toast.show", msg);
              }
            }
          }
        } catch (e) {
          // ignore
        }
        return Toast.show.call(this);
      };
    
    } catch (e) {
      console.log(`[-] Toast hook failed: ${e}`);
    }
    // -------------------------
    // Unified Java exit watchers
    // -------------------------
    function hookJavaMethod(clazz, method, detailFn) {
      try {
        const C = Java.use(clazz);
        const overs = C[method].overloads;
        overs.forEach(function (ov) {
          ov.implementation = function () {
            let detail = "";
            try { detail = detailFn ? detailFn(this, arguments) : ""; } catch (e) {}
            triggerRootDetection(`java:${clazz}.${method}`, detail, null, this);
            return ov.apply(this, arguments);
          };
        });
      } catch (e) {
        // ignore if class/method not present
      }
    }

    hookJavaMethod("java.lang.System", "exit", (_, args) => `code=${args[0]}`);
    hookJavaMethod("java.lang.Runtime", "exit", (_, args) => `code=${args[0]}`);
    hookJavaMethod("android.os.Process", "killProcess", (_, args) => `pid=${args[0]}`);

    hookJavaMethod("android.app.Activity", "finish", self => `${self.getClass().getName()}`);
    hookJavaMethod("android.app.Activity", "finishAffinity", self => `${self.getClass().getName()}`);

    console.log("[+] Unified RootDetect trigger loaded (native + Java).");
  });
}
