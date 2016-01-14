/*
 * Copyright 2015, Yahoo Inc.
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in project root for terms.
 */
package com.yahoo.elide.security.permissions.expressions;

import com.yahoo.elide.security.permissions.ExpressionResult;

import java.util.Optional;

/**
 * Expression for joining specific fields.
 */
public class SpecificFieldExpression implements Expression {
    private final Expression entityExpression;
    private final Optional<Expression> fieldExpression;

    public SpecificFieldExpression(final Expression entityExpression, final Expression fieldExpression) {
        this.entityExpression = entityExpression;
        this.fieldExpression = Optional.ofNullable(
                (fieldExpression instanceof NoopExpression) ? null : fieldExpression);
    }

    @Override
    public ExpressionResult evaluate() {
        if (!fieldExpression.isPresent()) {
            return entityExpression.evaluate();
        }
        return fieldExpression.get().evaluate();
    }
}
