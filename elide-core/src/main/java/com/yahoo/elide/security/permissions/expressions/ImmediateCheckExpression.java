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

import static com.yahoo.elide.security.permissions.ExpressionResult.FAIL;
import static com.yahoo.elide.security.permissions.ExpressionResult.PASS;

import java.util.Map;
import java.util.Optional;

/**
 * Expression for executing all specified checks.
 */
public class ImmediateCheckExpression implements Expression {
    protected final Check check;
    private final PersistentResource resource;
    private final Optional<ChangeSpec> changeSpec;
    private final Map<Check, ExpressionResult> cache;

    /**
     * Constructor.
     *
     * @param check Check
     * @param resource Persistent resource
     * @param changeSpec ChangeSpec
     * @param cache Cache
     */
    public ImmediateCheckExpression(final Check check,
                                    final PersistentResource resource,
                                    final ChangeSpec changeSpec,
                                    final Map<Check, ExpressionResult> cache) {
        this.check = check;
        this.resource = resource;
        this.changeSpec = Optional.ofNullable(changeSpec);
        this.cache = cache;
    }

    @Override
    public ExpressionResult evaluate() {
        return cache.computeIfAbsent(check, (chk) ->
            chk.ok(resource.getObject(), resource.getRequestScope(), changeSpec) ? PASS : FAIL
        );
    }
}
