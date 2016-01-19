/*
 * Copyright 2015, Yahoo Inc.
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in project root for terms.
 */
package com.yahoo.elide.security.permissions;

import com.yahoo.elide.audit.InvalidSyntaxException;
import com.yahoo.elide.core.PersistentResource;
import com.yahoo.elide.security.ChangeSpec;
import com.yahoo.elide.security.checks.Check;
import com.yahoo.elide.security.checks.ExtractedChecks;
import com.yahoo.elide.security.permissions.expressions.AndExpression;
import com.yahoo.elide.security.permissions.expressions.AnyFieldExpression;
import com.yahoo.elide.security.permissions.expressions.DeferredCheckExpression;
import com.yahoo.elide.security.permissions.expressions.Expression;
import com.yahoo.elide.security.permissions.expressions.ImmediateCheckExpression;
import com.yahoo.elide.security.permissions.expressions.OrExpression;
import com.yahoo.elide.security.permissions.expressions.SpecificFieldExpression;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import static com.yahoo.elide.security.checks.ExtractedChecks.CheckMode.ALL;
import static com.yahoo.elide.security.checks.ExtractedChecks.CheckSubset;

import java.lang.annotation.Annotation;
import java.util.HashMap;
import java.util.List;
import java.util.Queue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.function.BiFunction;
import java.util.function.Function;

/**
 * Expression builder to parse annotations and express the result as the Expression AST.
 */
@Slf4j
public class ExpressionBuilder {
    private final HashMap<Check, ExpressionResult> cache = new HashMap<>();

    private static final BiFunction<Expression, Expression, Expression> ALL_JOINER = AndExpression::new;
    private static final BiFunction<Expression, Expression, Expression> ANY_JOINER = OrExpression::new;

    /**
     * Build an expression that checks a specific field.
     *
     * @param resource Resource
     * @param annotationClass Annotation calss
     * @param field Field
     * @param changeSpec Change spec
     * @param <A> Type parameter
     * @return Commit and operation expressions
     */
    public <A extends Annotation> Expressions buildSpecificFieldExpression(final PersistentResource resource,
                                                                           final Class<A> annotationClass,
                                                                           final String field,
                                                                           final ChangeSpec changeSpec) {
        ExtractedChecks extracted = new ExtractedChecks(resource, annotationClass, field);

        Expression operationExpression =
                buildFullExpression(extracted.getEntityChecks(),
                                    extracted.getFieldChecks(),
                                    (check) -> new DeferredCheckExpression(check, resource, changeSpec, cache),
                                    SpecificFieldExpression::new);
        Expression commitExpression =
                buildFullExpression(extracted.getEntityChecks(),
                                    extracted.getFieldChecks(),
                                    (check) -> new ImmediateCheckExpression(check, resource, changeSpec, cache),
                                    SpecificFieldExpression::new);

        return new Expressions(operationExpression, commitExpression);
    }

    /**
     * Build an expression that checks any field on a bean.
     *
     * @param resource Resource
     * @param annotationClass annotation class
     * @param changeSpec change spec
     * @param <A> type parameter
     * @return Commit and operation expressions
     */
    public <A extends Annotation> Expressions buildAnyFieldExpression(final PersistentResource resource,
                                                                      final Class<A> annotationClass,
                                                                      final ChangeSpec changeSpec) {

        Function<Check, Expression> deferredCheckBuilder =
                (check) -> new DeferredCheckExpression(check, resource, changeSpec, cache);
        Function<Check, Expression> immediateCheckBuilder =
                (check) -> new ImmediateCheckExpression(check, resource, changeSpec, cache);

        List<String> fields = resource.getDictionary().getAllFields(resource.getObject());

        ExtractedChecks entity = new ExtractedChecks(resource, annotationClass);
        Expression opExp =
                buildFullExpression(entity.getEntityChecks(),
                                    entity.getFieldChecks(),
                                    deferredCheckBuilder,
                                    AnyFieldExpression::new);
        Expression comExp =
                buildFullExpression(entity.getEntityChecks(),
                                    entity.getFieldChecks(),
                                    immediateCheckBuilder,
                                    AnyFieldExpression::new);
        for (String field : fields) {
            ExtractedChecks extracted = new ExtractedChecks(resource, annotationClass, field);

            Expression operationExpression =
                    buildFullExpression(extracted.getEntityChecks(),
                                        extracted.getFieldChecks(),
                                        (check) -> new DeferredCheckExpression(check, resource, changeSpec, cache),
                                        AnyFieldExpression::new);
            Expression commitExpression =
                    buildFullExpression(extracted.getEntityChecks(),
                                        extracted.getFieldChecks(),
                                        (check) -> new ImmediateCheckExpression(check, resource, changeSpec, cache),
                                        AnyFieldExpression::new);
            opExp = new OrExpression(opExp, operationExpression);
            comExp = new OrExpression(comExp, commitExpression);
        }

        return new Expressions(opExp, comExp);
    }

    /**
     * Build a full/joined expression
     *
     * @param extractedEntity Entity checks
     * @param extractedFields Field checks
     * @param expressionBuilder Builder function to construct checks
     * @param expressionJoiner Final joining function to combine checks
     * @return Full expression
     */
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

    /**
     * Build a specific expression for a check.
     *
     * @param checks Checks to build expression for
     * @param expressionBuilder Builder method to convert check to an expression
     * @param expressionJoiner Method to join checks
     * @return Expression
     */
    private Expression buildExpression(final Queue<Class<? extends Check>> checks,
                                       final Function<Check, Expression> expressionBuilder,
                                       final BiFunction<Expression, Expression, Expression> expressionJoiner) {
        if (checks.size() == 0) {
            return null;
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

    /**
     * Structure containing built expressions.
     */
    @AllArgsConstructor
    public static class Expressions {
        @Getter private final Expression operationExpression;
        @Getter private final Expression commitExpression;
    }
}
