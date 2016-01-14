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
import com.yahoo.elide.security.checks.OperationCheck;
import com.yahoo.elide.security.permissions.ExpressionResult;

import static com.yahoo.elide.security.permissions.ExpressionResult.DEFERRED;

/**
 * Expression for representing commit checks.
 */
public class CommitCheckExpression extends OperationCheckExpression {

    /**
     * Constructor.
     *
     * @param check Check
     * @param resource Persistent resource
     * @param changeSpec Change spec
     */
    public CommitCheckExpression(final Check check, final PersistentResource resource, final ChangeSpec changeSpec) {
        super(check, resource, changeSpec);
    }

    @Override
    public ExpressionResult evaluate() {
        if (check instanceof CommitCheck && !(check instanceof OperationCheck)) {
            return DEFERRED;
        }
        return super.evaluate();
    }
}
