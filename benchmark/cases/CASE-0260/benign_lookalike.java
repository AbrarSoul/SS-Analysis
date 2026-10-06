package net.sourceforge.plantuml.directdot;

/**
 * Standalone example of the same shape: a format gate that skips an expensive
 * or format-specific step, but for a purely cosmetic reason (some renderers
 * do not support a decorative watermark), not a security boundary.
 */
public class WatermarkGate {

    public static boolean supportsWatermark(String rendererName) {
        return !"ascii-art".equals(rendererName);
    }
}
