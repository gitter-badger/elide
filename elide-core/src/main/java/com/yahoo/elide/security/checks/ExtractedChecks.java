/*
 * Copyright 2015, Yahoo Inc.
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in project root for terms.
 */
package com.yahoo.elide.security.checks;

import com.yahoo.elide.audit.InvalidSyntaxException;
import com.yahoo.elide.core.PersistentResource;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import java.lang.annotation.Annotation;
import java.util.ArrayList;

/**
 * Extracted checks.
 */
@Slf4j
public class ExtractedChecks {
    private final Class<? extends Check>[] anyEntityChecks;
    private final Class<? extends Check>[] allEntityChecks;
    private final Class<? extends Check>[] anyFieldChecks;
    private final Class<? extends Check>[] allFieldChecks;

    /**
     * Constructor.
     *
     * @param resource Resource
     * @param annotationClass Annotation class
     * @param <A> Type parameter
     */
    public <A extends Annotation> ExtractedChecks(final PersistentResource resource, final Class<A> annotationClass) {
        this(resource, annotationClass, null);
    }

    /**
     * Constructor.
     *
     * @param resource Resource
     * @param annotationClass Annotation class
     * @param field Field
     * @param <A> Type parameter
     */
    public <A extends Annotation> ExtractedChecks(final PersistentResource resource,
                                                  final Class<A> annotationClass,
                                                  final String field) {
        final A entityAnnotation = resource.getDictionary().getAnnotation(resource, annotationClass);
        final A fieldAnnotation = (field == null) ? null
                                                  : resource.getDictionary().getAttributeOrRelationAnnotation(
                                                        resource.getResourceClass(),
                                                        annotationClass,
                                                        field);
        // No checks specified
        if (entityAnnotation == null) {
            anyEntityChecks = null;
            allEntityChecks = null;
        } else {
            try {
                anyEntityChecks = (Class<? extends Check>[]) annotationClass
                        .getMethod("any").invoke(entityAnnotation, (Object[]) null);
                allEntityChecks = (Class<? extends Check>[]) annotationClass
                        .getMethod("all").invoke(entityAnnotation, (Object[]) null);
            } catch (ReflectiveOperationException e) {
                log.warn("Unknown permission: {}, {}", annotationClass.getName(), e);
                throw new InvalidSyntaxException("Unknown permission '" + annotationClass.getName() + "'", e);
            }
            if (anyEntityChecks.length <= 0 && allEntityChecks.length <= 0) {
                log.warn("Unknown permission: {}, {}", annotationClass.getName());
                throw new InvalidSyntaxException("Unknown permission '" + annotationClass.getName() + "'");
            }
        }

        if (fieldAnnotation == null) {
            anyFieldChecks = null;
            allFieldChecks = null;
        } else {
            try {
                anyFieldChecks = (Class<? extends Check>[]) annotationClass
                        .getMethod("any").invoke(fieldAnnotation, (Object[]) null);
                allFieldChecks = (Class<? extends Check>[]) annotationClass
                        .getMethod("all").invoke(fieldAnnotation, (Object[]) null);
            } catch (ReflectiveOperationException e) {
                log.warn("Unknown permission: {}, {}", annotationClass.getName(), e);
                throw new InvalidSyntaxException("Unknown permission '" + annotationClass.getName() + "'", e);
            }
            if (anyFieldChecks.length <= 0 && allFieldChecks.length <= 0) {
                log.warn("Unknown permission: {}, {}", annotationClass.getName());
                throw new InvalidSyntaxException("Unknown permission '" + annotationClass.getName() + "'");
            }
        }
    }

    @SuppressWarnings("unchecked")
    public Class<? extends Check>[] getCompleteSetOfEntityChecks() {
        return (anyEntityChecks != null && anyEntityChecks.length > 0) ? anyEntityChecks : allEntityChecks;
    }

    @SuppressWarnings("unchecked")
    public Class<? extends Check>[] getCompleteSetOfFieldChecks() {
        return (anyFieldChecks != null && anyFieldChecks.length > 0) ? anyFieldChecks : allFieldChecks;
    }

    public CheckMode getEntityCheckMode() {
        return (anyEntityChecks != null && anyEntityChecks.length > 0) ? CheckMode.ANY : CheckMode.ALL;
    }

    public CheckMode getFieldCheckMode() {
        return (anyFieldChecks != null && anyFieldChecks.length > 0) ? CheckMode.ANY : CheckMode.ALL;
    }

    public CheckSubset getEntityChecks() {
        return new CheckSubset(getCompleteSetOfEntityChecks(), getEntityCheckMode());
    }

    public CheckSubset getFieldChecks() {
        return new CheckSubset(getCompleteSetOfFieldChecks(), getFieldCheckMode());
    }

    public CheckSubset getEntityCommitChecks() {
        return new CheckSubset(getArray(CommitCheck.class, getCompleteSetOfEntityChecks()), getEntityCheckMode());
    }

    public CheckSubset getEntityOperationChecks() {
        return new CheckSubset(getArray(OperationCheck.class, getCompleteSetOfEntityChecks()), getEntityCheckMode());
    }

    public CheckSubset getFieldCommitChecks() {
        return new CheckSubset(getArray(CommitCheck.class, getCompleteSetOfFieldChecks()), getFieldCheckMode());
    }

    public CheckSubset getFieldOperationChecks() {
        return new CheckSubset(getArray(OperationCheck.class, getCompleteSetOfFieldChecks()), getFieldCheckMode());
    }

    @SuppressWarnings("unchecked")
    private static <T extends Check> Class<T>[] getArray(Class<T> cls, Class<? extends Check>[] checks) {
        if (checks == null) {
            return new Class[0];
        }
        ArrayList<Class<T>> checksList = new ArrayList<>();
        for (Class<? extends Check> check : checks) {
            if (cls.isAssignableFrom(check)) {
                checksList.add((Class<T>) check);
            }
        }
        return checksList.toArray(new Class[checksList.size()]);
    }

    /**
     * Class containing grouped information.
     */
    @AllArgsConstructor
    public static final class CheckSubset {
        @Getter private final Class<? extends Check>[] checks;
        @Getter private final CheckMode mode;
    }

    /**
     * Check mode.
     */
    public enum CheckMode {
        ANY,
        ALL
    }
}
