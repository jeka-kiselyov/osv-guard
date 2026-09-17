/** Severity bands, ordered least to most severe. `unknown` sits outside the order. */
export const BANDS = ['low', 'moderate', 'high', 'critical'];
/** Rank used for threshold comparisons. `unknown` is deliberately not rankable. */
export const BAND_RANK = {
    low: 1,
    moderate: 2,
    high: 3,
    critical: 4,
};
