/*
 * Copyright 2015, Yahoo Inc.
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in project root for terms.
 */
package com.yahoo.elide.security.permissions.expressions;

import com.yahoo.elide.core.PersistentResource;
import com.yahoo.elide.security.ChangeSpec;
import com.yahoo.elide.security.checks.Check;
import com.yahoo.elide.security.permissions.ExpressionResult;

import static com.yahoo.elide.security.permissions.ExpressionResult.DEFERRED;
import static com.yahoo.elide.security.permissions.ExpressionResult.FAIL;
import static com.yahoo.elide.security.permissions.ExpressionResult.PASS;

import java.util.Optional;

/**
 * Expression for operation checks (Expression terminal).
 */
public class OperationCheckExpression implements Expression {
    protected final Check check;
    private final PersistentResource resource;
    private final Optional<ChangeSpec> changeSpec;

    /**
     * Constructor.
     *
     * @param check Check
     * @param resource Persistent resource
     * @param changeSpec ChangeSpec
     */
    public OperationCheckExpression(final Check check,
                                    final PersistentResource resource,
                                    final ChangeSpec changeSpec) {
        this.check = check;
        this.resource = resource;
        this.changeSpec = Optional.ofNullable(changeSpec);
    }

    @Override
    public ExpressionResult evaluate() {
        // TODO: Caching
        if (check instanceof NoopExpression) {
            return DEFERRED;
        }
        return check.ok(resource.getObject(), resource.getRequestScope(), changeSpec) ? PASS : FAIL;
    }
}
