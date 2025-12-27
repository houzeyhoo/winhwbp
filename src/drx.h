#ifndef WINHWBP_DRX_H
#define WINHWBP_DRX_H

#define DR6_BC_POS(n) (n)
#define DR6_BC_MASK(n) (0x1u << DR6_BC_POS(n))

#define DR7_LE_POS(n) ((n) * 2u)
#define DR7_LE_MASK(n) (0x1u << DR7_LE_POS(n))

#define DR7_GE_POS(n) ((n) * 2 + 1u)
#define DR7_GE_MASK(n) (0x1u << DR7_GE_POS(n))

#define DR7_COND_POS(n) ((n) * 4 + 16u)
#define DR7_COND_MASK(n) (0x3u << DR7_COND_POS(n))

#define DR7_LEN_POS(n) ((n) * 4 + 18u)
#define DR7_LEN_MASK(n) (0x3u << DR7_LEN_POS(n))

#define DR7_LE_GE_NIB_MASK(n) (0x3u << DR7_LE_POS(n))
#define DR7_COND_LEN_NIB_MASK(n) (0xFu << DR7_COND_POS(n))

#endif /* WINHWBP_DRX_H */
