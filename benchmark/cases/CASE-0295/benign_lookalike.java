package org.springframework.beans;

import java.beans.PropertyDescriptor;

/**
 * Standalone example of the same shape: skip a well-known, harmless
 * "class" bookkeeping property when listing bean properties for a
 * documentation table (display filtering only, not a binding decision).
 */
class DocPropertyFilter {

    static boolean shouldList(PropertyDescriptor pd) {
        return !"class".equals(pd.getName());
    }
}
