// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.core;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

// Collects what instrumented applet code calls and reports it when the scope closes
public final class CallLog {
    private static final Logger log = LoggerFactory.getLogger("pro.javacard.engine.trace");
    private static final String INDENT = System.lineSeparator() + "  ";

    public enum Mode {
        TRACE,
        COUNT,
        STREAM
    }

    private final Mode mode;
    private final List<String> calls = new ArrayList<>();

    public CallLog(Mode mode) {
        this.mode = mode;
    }

    public void record(String label) {
        if (mode == Mode.STREAM) {
            log.info(label);
            return;
        }
        calls.add(label);
    }

    public void report() {
        if (calls.isEmpty()) {
            return;
        }
        if (mode == Mode.COUNT) {
            log.info("counts:{}", indented(counted()));
        } else {
            log.info("calls:{}", indented(calls));
        }
        calls.clear();
    }

    private List<String> counted() {
        var totals = new HashMap<String, Integer>();
        for (String call : calls) {
            totals.merge(call, 1, Integer::sum);
        }
        return totals.entrySet().stream()
                .sorted(Map.Entry.<String, Integer>comparingByValue().reversed().thenComparing(Map.Entry.comparingByKey()))
                .map(e -> String.format("%5d %s", e.getValue(), e.getKey()))
                .toList();
    }

    private static String indented(List<String> lines) {
        return lines.stream().collect(Collectors.joining(INDENT, INDENT, ""));
    }
}
