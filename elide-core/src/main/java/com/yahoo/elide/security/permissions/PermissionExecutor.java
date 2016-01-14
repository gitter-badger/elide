/*
 * Copyright 2015, Yahoo Inc.
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in project root for terms.
 */
package com.yahoo.elide.security.permissions;

import com.yahoo.elide.annotation.CreatePermission;
import com.yahoo.elide.annotation.UpdatePermission;
import com.yahoo.elide.audit.InvalidSyntaxException;
import com.yahoo.elide.core.PersistentResource;
import com.yahoo.elide.core.exceptions.ForbiddenAccessException;
import com.yahoo.elide.security.ChangeSpec;
import com.yahoo.elide.security.checks.Check;
import com.yahoo.elide.security.checks.ExtractedChecks;
import com.yahoo.elide.security.permissions.expressions.AndExpression;
import com.yahoo.elide.security.permissions.expressions.AnyFieldExpression;
import com.yahoo.elide.security.permissions.expressions.CommitCheckExpression;
import com.yahoo.elide.security.permissions.expressions.Expression;
import com.yahoo.elide.security.permissions.expressions.NoopExpression;
import com.yahoo.elide.security.permissions.expressions.OperationCheckExpression;
import com.yahoo.elide.security.permissions.expressions.OrExpression;
import com.yahoo.elide.security.permissions.expressions.SpecificFieldExpression;
import lombok.extern.slf4j.Slf4j;

import static com.yahoo.elide.security.permissions.ExpressionResult.DEFERRED;
import static com.yahoo.elide.security.permissions.ExpressionResult.FAIL;

import static com.yahoo.elide.security.checks.ExtractedChecks.CheckMode.ALL;
import static com.yahoo.elide.security.checks.ExtractedChecks.CheckSubset;

import java.lang.annotation.Annotation;
import java.util.ArrayList;
import java.util.List;
import java.util.Queue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.function.BiFunction;
import java.util.function.Function;

/**
 * Execute permission expressions.
 */
@Slf4j
public class PermissionExecutor {
    private final Queue<Expression> commitCheckQueue = new LinkedBlockingQueue<>();
    // TODO: Cache.

    private static final BiFunction<Expression, Expression, Expression> ALL_JOINER = AndExpression::new;
    private static final BiFunction<Expression, Expression, Expression> ANY_JOINER = OrExpression::new;

    public <A extends Annotation> void checkSpecificFieldPermission(final PersistentResource resource,
                                                                    final Class<A> annotationClass,
                                                                    final String field,
                                                                    final ChangeSpec changeSpec) {
        ExtractedChecks extracted = new ExtractedChecks(resource, annotationClass, field);

        Expression operationExpression =
                buildFullExpression(extracted.getEntityChecks(), extracted.getFieldChecks(),
                (check) -> new CommitCheckExpression(check, resource, changeSpec),  SpecificFieldExpression::new);
        Expression commitExpression =
                buildFullExpression(extracted.getEntityChecks(), extracted.getFieldChecks(),
                (check) -> new OperationCheckExpression(check, resource, changeSpec), SpecificFieldExpression::new);

        executeExpressions(operationExpression, commitExpression, annotationClass);
    }

    public <A extends Annotation> void checkAnyFieldPermission(final PersistentResource resource,
                                                               final Class<A> annotationClass,
                                                               final ChangeSpec changeSpec) {
        // TODO: Clean this up.
        List<String> fields = new ArrayList<>();

        List<String> attrs = resource.getDictionary().getAttributes(resource.getResourceClass());
        List<String> rels = resource.getDictionary().getRelationships(resource.getResourceClass());

        if (attrs != null) {
            fields.addAll(attrs);
        }

        if (rels != null) {
            fields.addAll(rels);
        }

        ExtractedChecks entity = new ExtractedChecks(resource, annotationClass);
        Expression opExp = buildFullExpression(entity.getEntityChecks(), entity.getFieldChecks(),
                (check) -> new CommitCheckExpression(check, resource, changeSpec), AnyFieldExpression::new);
        Expression comExp = buildFullExpression(entity.getEntityChecks(), entity.getFieldChecks(),
                (check) -> new OperationCheckExpression(check, resource, changeSpec), AnyFieldExpression::new);
        for (String field : fields) {
            ExtractedChecks extracted = new ExtractedChecks(resource, annotationClass, field);

            Expression operationExpression =
                    buildFullExpression(extracted.getEntityChecks(), extracted.getFieldChecks(),
                            (check) -> new CommitCheckExpression(check, resource, changeSpec),
                            AnyFieldExpression::new);
            Expression commitExpression =
                    buildFullExpression(extracted.getEntityChecks(), extracted.getFieldChecks(),
                            (check) -> new OperationCheckExpression(check, resource, changeSpec),
                            AnyFieldExpression::new);
            opExp = new OrExpression(opExp, operationExpression);
            comExp = new OrExpression(comExp, commitExpression);
        }

        executeExpressions(opExp, comExp, annotationClass);
    }

    /**
     * Evaluate commit check permissions.
     */
    public void checkCommitPermissions() {
        commitCheckQueue.forEach((expr) -> {
            if (expr.evaluate() == FAIL && !(expr instanceof NoopExpression)) {
                throw new ForbiddenAccessException();
            }
        });
    }

    private <A extends Annotation> void executeExpressions(final Expression operationExpressions,
                                                           final Expression commitExpressions,
                                                           final Class<A> annotationClass) {
        if (UpdatePermission.class.isAssignableFrom(annotationClass)
                || CreatePermission.class.isAssignableFrom(annotationClass)) {
            ExpressionResult result = operationExpressions.evaluate();
            if (result == DEFERRED) {
                commitCheckQueue.add(commitExpressions);
            } else if (result == FAIL) {
                throw new ForbiddenAccessException();
            }
        } else {
            if (commitExpressions.evaluate() == FAIL) {
                throw new ForbiddenAccessException();
            }
        }
    }

    private Expression buildFullExpression(final CheckSubset extractedEntity,
                                           final CheckSubset extractedFields,
                                           final Function<Check, Expression> expressionBuilder,
                                           final BiFunction<Expression, Expression, Expression> expressionJoiner) {
        final Queue<Class<? extends Check>> entityChecks = arrayToQueue(extractedEntity.getChecks());
        final Queue<Class<? extends Check>> fieldChecks = arrayToQueue(extractedFields.getChecks());

        BiFunction<Expression, Expression, Expression> entityJoiner =
                (extractedEntity.getMode() == ALL) ? ALL_JOINER : ANY_JOINER;
        BiFunction<Expression, Expression, Expression> fieldJoiner =
                (extractedFields.getMode() == ALL) ? ALL_JOINER : ANY_JOINER;

        return expressionJoiner.apply(
                buildExpression(entityChecks, expressionBuilder, entityJoiner),
                buildExpression(fieldChecks, expressionBuilder, fieldJoiner));
    }

    private Expression buildExpression(final Queue<Class<? extends Check>> checks,
                                       final Function<Check, Expression> expressionBuilder,
                                       final BiFunction<Expression, Expression, Expression> expressionJoiner) {
        if (checks.size() == 0) {
            return new NoopExpression();
        }

        try {
            Check instance = checks.poll().newInstance();
            Expression expression = expressionBuilder.apply(instance);
            return expressionJoiner.apply(expression, buildExpression(checks, expressionBuilder, expressionJoiner));
        } catch (InstantiationException | IllegalAccessException e) {
            log.error("Could not access check. Exception: {}", e);
            throw new InvalidSyntaxException("Could not instantiate specified check.");
        }
    }

    /**
     * Convert an array to queue.
     *
     * @param array Array to convert
     * @param <T> Type parameter
     * @return Queue representing array. Empty queue if array is null.
     */
    private static <T> Queue<T> arrayToQueue(final T[] array) {
        final Queue<T> queue = new LinkedBlockingQueue<>();
        if (array == null) {
            return queue;
        }
        for (T value : array) {
            queue.add(value);
        }
        return queue;
    }
}
