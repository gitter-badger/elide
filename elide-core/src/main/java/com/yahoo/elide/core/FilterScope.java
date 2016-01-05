/*
 * Copyright 2015, Yahoo Inc.
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in project root for terms.
 */
package com.yahoo.elide.core;

import com.yahoo.elide.optimization.UserCheck;
import com.yahoo.elide.optimization.UserCheck.UserPermission;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static com.yahoo.elide.optimization.UserCheck.ALLOW;
import static com.yahoo.elide.optimization.UserCheck.DENY;
import static com.yahoo.elide.optimization.UserCheck.FILTER;

/**
 * Scope for filter processing.  Contains requestScope and checks.
 * @param <T> Filter type
 */
@Slf4j
public class FilterScope<T> {

    @Getter private final RequestScope requestScope;
    @Getter private final boolean isAny;
    @Getter private final List<UserCheck> userChecks;
    private UserPermission filterUserPermission = null;

    public FilterScope(RequestScope requestScope) {
        this.requestScope = requestScope;
        this.isAny = false;
        userChecks = Collections.emptyList();
    }

    public FilterScope(RequestScope requestScope,
                       boolean isAny,
                       Class<? extends UserCheck>[] userCheckClasses) {
        this.requestScope = requestScope;
        this.isAny = isAny;

        List<UserCheck> userChecks = new ArrayList<>(userCheckClasses.length);
        for (Class<? extends UserCheck> checkClass : userCheckClasses) {
            try {
                userChecks.add(checkClass.newInstance());
            } catch (InstantiationException | IllegalAccessException e) {
                log.debug("Could not instantiate UserCheck: {}", checkClass.getName());
                throw new IllegalStateException("Failed to instantiate UserCheck.");
            }
        }
        this.userChecks = userChecks;
    }

    /**
     * Returns true if filters are applied to this query.
     *
     * @return true if there are filters
     */
    public boolean hasPredicates() {
        return !requestScope.getPredicates().isEmpty();
    }

    /**
     * Get User Permissions.
     *
     * @return composite UserPermission for this FilterScope
     */
    public UserPermission getUserPermission() {
        if (filterUserPermission != null) {
            return filterUserPermission;
        }

        UserPermission compositeUserPermission = null;
        for (UserCheck check : userChecks) {
            UserPermission checkUserPermission = requestScope.getUser().checkUserPermission(check);

            // short-cut for ALLOW and ANY
            if (checkUserPermission == ALLOW && isAny) {
                compositeUserPermission = ALLOW;
                break;
            }

            // short-cut for DENY and ALL
            if (checkUserPermission == DENY && !isAny) {
                compositeUserPermission = DENY;
                break;
            }

            // if FILTER set as found and keep looking
            if (checkUserPermission == FILTER) {
                compositeUserPermission = FILTER;
            }
        }

        // if still null, then all are DENY & ALL or ALLOW & ANY
        if (compositeUserPermission == null) {
            compositeUserPermission = isAny ? DENY : ALLOW;
        }
        return this.filterUserPermission = compositeUserPermission;
    }
}
