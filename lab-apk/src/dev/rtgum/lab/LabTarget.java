package dev.rtgum.lab;

/**
 * The acceptance fixture for the ART (mako) hook path.
 *
 * <p>Both methods are deliberately trivial and static so that their
 * {@code ArtMethod} records are compact, adjacent, and independently
 * observable. {@link #add} is the hook target; {@link #untouched} is the
 * same-page control that must keep returning its original value, which is what
 * proves the shadow-page patch is field-scoped rather than page-scoped.
 *
 * <p>They are declared in the same class on purpose: the runtime lays
 * ArtMethod records for one class out contiguously, so the two records usually
 * share a data page. That adjacency is what makes {@code untouched} a real
 * control for the "same page, multiple ArtMethod" requirement.
 */
public final class LabTarget {

    private LabTarget() {
    }

    /** Hook target: the framework rewrites this to 42. */
    public static int add(int a, int b) {
        return a + b;
    }

    /** Same-page control: no hook is installed, so the value must not change. */
    public static int untouched(int a, int b) {
        return a + b;
    }

    /** A second arithmetic result, so the lab can show the control next to it. */
    public static int baseline() {
        return add(1, 2);
    }
}
