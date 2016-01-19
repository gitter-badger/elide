/*
 * Copyright 2015, Yahoo Inc.
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in project root for terms.
 */
package com.yahoo.elide.security.permissions.expressions;

import com.yahoo.elide.security.permissions.ExpressionResult;

import static com.yahoo.elide.security.permissions.ExpressionResult.FAIL;
import static com.yahoo.elide.security.permissions.ExpressionResult.PASS;

/**
 * Implementation of joining expression results by any field success or entity success.
 */
public class AnyFieldExpression implements Expression {
    private final Expression entityExpression;
    private final Expression fieldExpression;

    public AnyFieldExpression(final Expression entityExpression, final Expression fieldExpression) {
        this.entityExpression = entityExpression;
        this.fieldExpression = fieldExpression;
    }

    @Override
    public ExpressionResult evaluate() {
        ExpressionResult fieldResult = (fieldExpression == null) ? FAIL : fieldExpression.evaluate();
        if (fieldResult != ExpressionResult.FAIL) {
            return fieldResult;
        }
        return (entityExpression == null) ? PASS : entityExpression.evaluate();
    }
}
