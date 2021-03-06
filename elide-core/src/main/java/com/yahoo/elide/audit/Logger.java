/*
 * Copyright 2015, Yahoo Inc.
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in project root for terms.
 */
package com.yahoo.elide.audit;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Base Audit Logger
 * <p>
 * This class uses ThreadLocal list to be thread safe.
 */
public abstract class Logger {
    protected final ThreadLocal<List<LogMessage>> messages;

    public Logger() {
        messages = ThreadLocal.withInitial(() -> { return new ArrayList<>(); });
    }

    public void log(LogMessage message) {
        messages.get().add(message);
    }

    public abstract void commit() throws IOException;
}
