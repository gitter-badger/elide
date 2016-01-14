/*
 * Copyright 2015, Yahoo Inc.
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in project root for terms.
 */
package com.yahoo.elide.security.permissions.expressions;

import com.yahoo.elide.security.permissions.ExpressionResult;

import static com.yahoo.elide.security.permissions.ExpressionResult.FAIL;

/**
 * Expression representing no-ops.
 */
public class NoopExpression implements Expression {

    @Override
    public ExpressionResult evaluate() {
        return FAIL;
    }
}
