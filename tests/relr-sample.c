/*
 * Tiny shared object that produces R_AARCH64_RELATIVE relocations so the
 * NDK linker can pack them as DT_RELR. Visible-path RELR fixture only.
 */

int rtgum_relr_anchor = 0x11;
int *rtgum_relr_pointer = &rtgum_relr_anchor;

int rtgum_relr_value(void)
{
    return *rtgum_relr_pointer;
}
