/*
 * Copyright 2015, Yahoo Inc.
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in project root for terms.
 */
package com.yahoo.elide.security.permissions.expressions;

import com.yahoo.elide.core.PersistentResource;
import com.yahoo.elide.security.ChangeSpec;
import com.yahoo.elide.security.checks.Check;
import com.yahoo.elide.security.checks.CommitCheck;
import com.yahoo.elide.security.permissions.ExpressionResult;

import java.util.Map;

import static com.yahoo.elide.security.permissions.ExpressionResult.DEFERRED;

/**
 * Expression for only executing operation checks and skipping commit checks.
 */
public class DeferredCheckExpression extends ImmediateCheckExpression {

    /**
     * Constructor.
     *
     * @param check Check
     * @param resource Persistent resource
     * @param changeSpec Change spec
     * @param cache Cache
     */
    public DeferredCheckExpression(final Check check,
                                   final PersistentResource resource,
                                   final ChangeSpec changeSpec,
                                   final Map<Check, ExpressionResult> cache) {
        super(check, resource, changeSpec, cache);
    }

    @Override
    public ExpressionResult evaluate() {
        if (check instanceof CommitCheck) {
            return DEFERRED;
        }
        return super.evaluate();
    }
}
