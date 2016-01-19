/*
 * Copyright 2015, Yahoo Inc.
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in project root for terms.
 */
package com.yahoo.elide.security;

import com.yahoo.elide.annotation.CreatePermission;
import com.yahoo.elide.annotation.UpdatePermission;
import com.yahoo.elide.annotation.UserPermission;
import com.yahoo.elide.audit.InvalidSyntaxException;
import com.yahoo.elide.core.FilterScope;
import com.yahoo.elide.core.PersistentResource;
import com.yahoo.elide.core.RequestScope;

import com.yahoo.elide.core.SecurityMode;
import com.yahoo.elide.core.exceptions.ForbiddenAccessException;
import com.yahoo.elide.optimization.UserCheck;
import com.yahoo.elide.security.permissions.ExpressionBuilder;
import com.yahoo.elide.security.permissions.ExpressionResult;
import com.yahoo.elide.security.permissions.expressions.Expression;
import lombok.extern.slf4j.Slf4j;

import java.lang.annotation.Annotation;
import java.util.ArrayList;
import java.util.List;
import java.util.Queue;
import java.util.concurrent.LinkedBlockingQueue;

import static com.yahoo.elide.security.permissions.ExpressionResult.DEFERRED;
import static com.yahoo.elide.security.permissions.ExpressionResult.FAIL;
import static com.yahoo.elide.security.permissions.ExpressionBuilder.Expressions;

/**
 * Class responsible for managing the life-cycle and execution of checks.
 */
@Slf4j
public class PermissionManager {
    private final ExpressionBuilder expressionBuilder = new ExpressionBuilder();
    private final Queue<Expression> commitCheckQueue = new LinkedBlockingQueue<>();

    /**
     * Enum describing check combinators.
     */
    public enum CheckMode {
        ANY,
        ALL
    }

    /**
     * Load checks for filter scope.
     *
     * @param userPermission User permission to check
     * @param requestScope Request scope
     * @return Filter scope containing user permission checks.
     */
    public static FilterScope loadChecks(UserPermission userPermission, RequestScope requestScope) {
        if (userPermission == null) {
            return new FilterScope(requestScope);
        }

        Class<? extends UserCheck>[] anyChecks = userPermission.any();
        Class<? extends UserCheck>[] allChecks = userPermission.all();
        Class<? extends Annotation> annotationClass = userPermission.getClass();

        if (anyChecks.length > 0) {
            return new FilterScope(requestScope, CheckMode.ANY, instantiateUserChecks(anyChecks));
        } else if (allChecks.length > 0) {
            return new FilterScope(requestScope, CheckMode.ALL, instantiateUserChecks(allChecks));
        } else {
            log.warn("Unknown user permission '{}'", annotationClass.getName());
            throw new InvalidSyntaxException("Unknown user permission '" + annotationClass.getName() + "'");
        }
    }

    /**
     * Check permission on class.
     *
     * @param annotationClass annotation class
     * @param resource resource
     * @param <A> type parameter
     * @see com.yahoo.elide.annotation.CreatePermission
     * @see com.yahoo.elide.annotation.ReadPermission
     * @see com.yahoo.elide.annotation.UpdatePermission
     * @see com.yahoo.elide.annotation.DeletePermission
     */
    public <A extends Annotation> void checkPermission(Class<A> annotationClass, PersistentResource resource) {
        checkPermission(annotationClass, resource, null);
    }

    /**
     * Check permission on class.
     *
     * @param annotationClass annotation class
     * @param resource resource
     * @param changeSpec ChangeSpec
     * @param <A> type parameter
     * @see com.yahoo.elide.annotation.CreatePermission
     * @see com.yahoo.elide.annotation.ReadPermission
     * @see com.yahoo.elide.annotation.UpdatePermission
     * @see com.yahoo.elide.annotation.DeletePermission
     */
    public <A extends Annotation> void checkPermission(Class<A> annotationClass,
                                                       PersistentResource resource,
                                                       ChangeSpec changeSpec) {
        checkFieldAwarePermissions(resource, changeSpec, annotationClass);
    }

    /**
     * Check for permissions on a class and its fields.
     *
     * @param resource resource
     * @param changeSpec change spec
     * @param annotationClass annotation class
     * @param <A> type parameter
     */
    public <A extends Annotation> void checkFieldAwarePermissions(PersistentResource<?> resource,
                                                                  ChangeSpec changeSpec,
                                                                  Class<A> annotationClass) {
        if (resource.getRequestScope().getSecurityMode() == SecurityMode.BYPASS_SECURITY) {
            return; // Bypass
        }
        Expressions expressions =
                expressionBuilder.buildAnyFieldExpression(resource, annotationClass, changeSpec);
        executeExpressions(expressions, annotationClass);
    }

    /**
     * Check for permissions on a specific field.
     *
     * @param resource resource
     * @param changeSpec changepsec
     * @param annotationClass annotation class
     * @param field field to check
     * @param <A> type parameter
     */
    public <A extends Annotation> void checkFieldAwarePermissions(PersistentResource<?> resource,
                                                                  ChangeSpec changeSpec,
                                                                  Class<A> annotationClass,
                                                                  String field) {
        if (resource.getRequestScope().getSecurityMode() == SecurityMode.BYPASS_SECURITY) {
            return; // Bypass
        }
        Expressions expressions =
                expressionBuilder.buildSpecificFieldExpression(resource, annotationClass, field, changeSpec);
        executeExpressions(expressions, annotationClass);
    }

    /**
     * Execute commmit checks.
     */
    public void executeCommitChecks() {
        commitCheckQueue.forEach((expr) -> {
            if (expr.evaluate() == FAIL) {
                throw new ForbiddenAccessException();
            }
        });
    }

    /**
     * Execute expressions.
     *
     * @param expressions expressions to execute
     * @param annotationClass annotation
     * @param <A> type parameter
     */
    private <A extends Annotation> void executeExpressions(final ExpressionBuilder.Expressions expressions,
                                                           final Class<A> annotationClass) {
        if (UpdatePermission.class.isAssignableFrom(annotationClass)
                || CreatePermission.class.isAssignableFrom(annotationClass)) {
            ExpressionResult result = expressions.getOperationExpression().evaluate();
            if (result == DEFERRED) {
                commitCheckQueue.add(expressions.getCommitExpression());
            } else if (result == FAIL) {
                throw new ForbiddenAccessException();
            }
        } else {
            if (expressions.getCommitExpression().evaluate() == FAIL) {
                throw new ForbiddenAccessException();
            }
        }
    }

    /**
     * Instantiate a list of UserCheck's.
     *
     * @param userCheckClasses Array of classes to instantiate
     * @return List of ordered, instantiated UserCheck's
     */
    private static List<UserCheck> instantiateUserChecks(Class<? extends UserCheck>[] userCheckClasses) {
        List<UserCheck> userChecks = new ArrayList<>(userCheckClasses.length);
        for (Class<? extends UserCheck> checkClass : userCheckClasses) {
            try {
                userChecks.add(checkClass.newInstance());
            } catch (InstantiationException | IllegalAccessException e) {
                log.error("Could not instantiate UserCheck: {}", checkClass.getName());
                throw new IllegalStateException("Failed to instantiate UserCheck.");
            }
        }
        return userChecks;
    }
}
