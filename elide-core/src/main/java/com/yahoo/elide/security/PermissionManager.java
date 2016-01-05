/*
 * Copyright 2015, Yahoo Inc.
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in project root for terms.
 */
package com.yahoo.elide.security;

import com.google.common.base.Supplier;
import com.yahoo.elide.annotation.CreatePermission;
import com.yahoo.elide.annotation.UpdatePermission;
import com.yahoo.elide.audit.InvalidSyntaxException;
import com.yahoo.elide.core.EntityDictionary;
import com.yahoo.elide.core.PersistentResource;
import com.yahoo.elide.core.SecurityMode;
import com.yahoo.elide.core.exceptions.ForbiddenAccessException;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import java.lang.annotation.Annotation;
import java.util.*;
import java.util.function.BiFunction;

/**
 * Class responsible for managing the life-cycle and execution of checks
 */
@Slf4j
public class PermissionManager {
    private final LinkedHashSet<Supplier<Void>> commitChecks = new LinkedHashSet<>();

    /**
     * Enum describing check combinators
     */
    public enum CheckMode {
        ANY,
        ALL
    }

    /**
     * Extract a set of permissions from an annotation
     *
     * @param annotationClass Type of annotation to extract values
     * @param annotation Annotation instance to extract values
     * @param <A> type parameter
     * @return Extracted checks
     */
    @SuppressWarnings("unchecked")
    public static <A extends Annotation> ExtractedChecks extractChecks(Class<A> annotationClass, A annotation) {
        Class<? extends Check>[] anyChecks;
        Class<? extends Check>[] allChecks;
        try {
            anyChecks = (Class<? extends Check>[]) annotationClass
                    .getMethod("any").invoke(annotation, (Object[]) null);
            allChecks = (Class<? extends Check>[]) annotationClass
                    .getMethod("all").invoke(annotation, (Object[]) null);
        } catch (ReflectiveOperationException e) {
            log.debug("Unknown permission: {}, {}", annotationClass.getName(), e);
            throw new InvalidSyntaxException("Unknown permission " + annotationClass.getName(), e);
        }
        if (anyChecks.length <= 0 && allChecks.length <= 0) {
            log.debug("Unknown permission: {}, {}", annotationClass.getName());
            throw new InvalidSyntaxException("Unknown permission " + annotationClass.getName());
        }
        return new ExtractedChecks(anyChecks, allChecks);
    }

    public void checkPermissions(Class<? extends Check>[] checks,
                                 boolean isAny,
                                 PersistentResource<?> resource,
                                 Class<? extends Annotation> annotationClass) {
        checkPermissions(checks, isAny, resource, null, annotationClass);
    }

    public void checkPermissions(Class<? extends Check>[] checks,
                                boolean isAny,
                                PersistentResource<?> resource,
                                ChangeSpec<?> changeSpec,
                                Class<? extends Annotation> annotationClass) {
        runPermissionChecks(checks, isAny, resource, changeSpec, annotationClass, false);
    }

    public <A extends Annotation> void checkFieldAwarePermissions(PersistentResource<?> resource,
                                                                  ChangeSpec<?> changeSpec,
                                                                  Class<A> annotationClass) {
        EntityDictionary dictionary = resource.getDictionary();
        // Check full object, then all fields
        boolean hasPassingCheck = true;
        try {
            A annotation = dictionary.getAnnotation(resource, annotationClass);
            if (annotation != null) {
                ExtractedChecks extracted = extractChecks(annotationClass, annotation);
                boolean isAny = extracted.getAnyChecks().length > 0;
                Class<? extends Check>[] checks = (isAny) ? extracted.getAnyChecks() : extracted.getAllChecks();
                runPermissionChecks(checks, isAny, resource, changeSpec, annotationClass, true);
                // If this is an "any" check, then we're done. If it is an "all" check, we may have commit checks queued
                // up. This means we really need to check additional fields and queue up those checks as well.
                if (isAny) {
                    return;
                }
            }
        } catch (ForbiddenAccessException e) {
            // Ignore this and continue on to checking our fields
            hasPassingCheck = false;
        }

        Class<?> entityClass = resource.getResourceClass();
        List<String> attributes = dictionary.getAttributes(entityClass);
        List<String> relationships = dictionary.getRelationships(entityClass);
        List<String> fields = (attributes != null) ? new ArrayList<>(dictionary.getAttributes(entityClass))
                                                   : new ArrayList<>();
        if (relationships != null) {
            fields.addAll(relationships);
        }

        for (String field : fields) {
            A annotation = dictionary.getAttributeOrRelationAnnotation(entityClass, annotationClass, field);
            if (annotation == null) {
                continue;
            }
            ExtractedChecks extracted = extractChecks(annotationClass, annotation);
            try {
                boolean isAny = extracted.getAnyChecks().length > 0;
                Class<? extends Check>[] checks = (isAny) ? extracted.getAnyChecks() : extracted.getAllChecks();
                runPermissionChecks(checks, isAny, resource, changeSpec, annotationClass, true);
                if (isAny) {
                    return;
                }
                hasPassingCheck = true;
            } catch (ForbiddenAccessException e) {
                // Ignore and keep looking or queueing
            }
        }

        // If nothing succeeded, we know nothing is queued up. We should fail out.
        if (!hasPassingCheck) {
            throw new ForbiddenAccessException();
        }
    }

    public <A extends Annotation> void checkFieldAwarePermissions(PersistentResource<?> resource,
                                                                  ChangeSpec<?> changeSpec,
                                                                  Class<A> annotationClass,
                                                                  String field) {
        EntityDictionary dictionary = resource.getDictionary();
        // Check full object, then field
        boolean entityFailed = false;
        try {
            A annotation = dictionary.getAnnotation(resource, annotationClass);
            if (annotation != null) {
                ExtractedChecks extracted = extractChecks(annotationClass, annotation);
                boolean isAny = extracted.getAnyChecks().length > 0;
                Class<? extends Check>[] checks = (isAny) ? extracted.getAnyChecks() : extracted.getAllChecks();
                runPermissionChecks(checks, isAny, resource, changeSpec, annotationClass, true);
            }
        } catch (ForbiddenAccessException e) {
            // Ignore this and continue on to checking our fields
            entityFailed = true;
        }

        A annotation = dictionary.getAttributeOrRelationAnnotation(resource.getResourceClass(), annotationClass, field);
        if (annotation != null) {
            ExtractedChecks extracted = extractChecks(annotationClass, annotation);
            boolean isAny = extracted.getAnyChecks().length > 0;
            Class<? extends Check>[] checks = (isAny) ? extracted.getAnyChecks() : extracted.getAllChecks();
            runPermissionChecks(checks, isAny, resource, changeSpec, annotationClass, true);
        } else if (entityFailed) {
            throw new ForbiddenAccessException();
        }
    }

    public void executeCommitChecks() {
        commitChecks.forEach(Supplier::get);
    }

    private void runPermissionChecks(Class<? extends Check>[] checks,
                                     boolean isAny,
                                     PersistentResource<?> resource,
                                     ChangeSpec<?> changeSpec,
                                     Class<? extends Annotation> annotationClass,
                                     boolean isFieldAware) {
        if (resource.getRequestScope().getSecurityMode() == SecurityMode.BYPASS_SECURITY) {
            return;
        }

        BiFunction<Check, Optional<ChangeSpec<?>>, Boolean> checkFn =
                (check, changespec) -> check.ok(resource.getRequestScope(), changespec);

        boolean shouldDefer = CreatePermission.class.equals(annotationClass)
                || UpdatePermission.class.equals(annotationClass);

        if (!shouldDefer) {
            checkFn = (check, changespec) -> check.ok(resource.getRequestScope(), changespec)
                    && check.ok(resource.getObject(), resource.getRequestScope(), changespec);
        }

        executePermissions(checks,
                isAny ? CheckMode.ANY : CheckMode.ALL,
                resource,
                Optional.ofNullable(changeSpec),
                shouldDefer,
                isFieldAware,
                checkFn);
    }

    /**
     * Execute a set of permission checks.
     *
     * @param checks Array of Check annotations
     * @param mode true if ANY, else ALL
     * @param resource provided PersistentResource to check
     * @param changeSpec specification of changes
     * @param shouldDefer Determine whether or not this check should be re-run in its deferred form (i.e. commitCheck)
     * @param isFieldAware Determine whether or not this is a field-aware check
     * @param checkFn the function that actually executes the check so this logic can be reused
     */
    private void executePermissions(Class<? extends Check>[] checks,
                                    CheckMode mode,
                                    PersistentResource<?> resource,
                                    Optional<ChangeSpec<?>> changeSpec,
                                    boolean shouldDefer,
                                    boolean isFieldAware,
                                    BiFunction<Check, Optional<ChangeSpec<?>>, Boolean> checkFn) {
        for (Class<? extends Check> check : checks) {
            Check checkHandler;
            try {
                checkHandler = check.newInstance();
            } catch (InstantiationException | IllegalAccessException e) {
                log.debug("Illegal permission check {} {}", check.getName(), e);
                throw new InvalidSyntaxException("Illegal permission check " + check.getName(), e);
            }

            Boolean ok = checkFn.apply(checkHandler, changeSpec);

            if (ok == null) {
                ok = false;
            }

            if (ok && mode == CheckMode.ANY && !shouldDefer) {
                return;
            }

            if (!ok && mode == CheckMode.ALL) {
                log.debug("ForbiddenAccess {} {}#{}", check, resource.getType(), resource.getId());
                throw new ForbiddenAccessException();
            }

            // Add check to a list for later execution
            if (shouldDefer) {
                // Hrm so much reliance on side-effects :(
                // TODO: Hrm. If hashes don't match, this will probably be run far too many times...
                commitChecks.add(() -> {
                    executePermissions(checks,
                            mode,
                            resource,
                            changeSpec,
                            false,
                            isFieldAware,
                            (handler, changespec) ->
                                    handler.ok(resource.getObject(), resource.getRequestScope(), changespec));
                    return null;
                });
            }
        }

        if (mode == CheckMode.ANY && !shouldDefer) {
            log.debug("ForbiddenAccess {} {}#{}", Arrays.asList(checks), resource.getType(), resource.getId());
            throw new ForbiddenAccessException();
        }
    }

    /**
     * Extracted checks
     */
    @AllArgsConstructor
    public static final class ExtractedChecks {
        @Getter private final Class<? extends Check>[] anyChecks;
        @Getter private final Class<? extends Check>[] allChecks;
    }
}
