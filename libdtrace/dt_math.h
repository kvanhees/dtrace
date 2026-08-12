/*
 * Oracle Linux DTrace.
 * Copyright (c) 2009, 2026, Oracle and/or its affiliates. All rights reserved.
 * Licensed under the Universal Permissive License v 1.0 as shown at
 * http://oss.oracle.com/licenses/upl.
 */

#ifndef _DT_MATH_H
#define _DT_MATH_H

#ifdef  __cplusplus
extern "C" {
#endif

#define	DT_MASK_LO 0x00000000FFFFFFFFULL

/*
 * We declare this here because (1) we need it and (2) we want to avoid a
 * dependency on libm in libdtrace.
 */
static inline long double
dt_fabsl(long double x)
{
	if (x < 0)
		return -x;

	return x;
}

/*
 * 128-bit arithmetic functions needed to support the stddev() aggregating
 * action.
 */
static inline int
dt_gt_128(uint64_t *a, uint64_t *b)
{
	return a[1] > b[1] || (a[1] == b[1] && a[0] > b[0]);
}

static inline int
dt_ge_128(uint64_t *a, uint64_t *b)
{
	return a[1] > b[1] || (a[1] == b[1] && a[0] >= b[0]);
}

static inline int
dt_le_128(uint64_t *a, uint64_t *b)
{
	return a[1] < b[1] || (a[1] == b[1] && a[0] <= b[0]);
}

/*
 * Shift the 128-bit value in a by b. If b is positive, shift left.
 * If b is negative, shift right.
 */
static inline void
dt_shift_128(uint64_t *a, int b)
{
	uint64_t mask;

	if (b == 0)
		return;

	if (b < 0) {
		b = -b;
		if (b >= 64) {
			a[0] = a[1] >> (b - 64);
			a[1] = 0;
		} else {
			a[0] >>= b;
			mask = 1LL << (64 - b);
			mask -= 1;
			a[0] |= ((a[1] & mask) << (64 - b));
			a[1] >>= b;
		}
	} else {
		if (b >= 64) {
			a[1] = a[0] << (b - 64);
			a[0] = 0;
		} else {
			a[1] <<= b;
			mask = a[0] >> (64 - b);
			a[1] |= mask;
			a[0] <<= b;
		}
	}
}

static inline int
dt_nbits_128(uint64_t *a)
{
	int nbits = 0;
	uint64_t tmp[2];
	uint64_t zero[2] = { 0, 0 };

	tmp[0] = a[0];
	tmp[1] = a[1];

	dt_shift_128(tmp, -1);
	while (dt_gt_128(tmp, zero)) {
		dt_shift_128(tmp, -1);
		nbits++;
	}

	return nbits;
}

static inline void
dt_subtract_128(uint64_t *minuend, uint64_t *subtrahend, uint64_t *difference)
{
	uint64_t result[2];

	result[0] = minuend[0] - subtrahend[0];
	result[1] = minuend[1] - subtrahend[1] -
	    (minuend[0] < subtrahend[0] ? 1 : 0);

	difference[0] = result[0];
	difference[1] = result[1];
}

static inline void
dt_add_128(uint64_t *addend1, uint64_t *addend2, uint64_t *sum)
{
	uint64_t result[2];

	result[0] = addend1[0] + addend2[0];
	result[1] = addend1[1] + addend2[1] +
	    (result[0] < addend1[0] || result[0] < addend2[0] ? 1 : 0);

	sum[0] = result[0];
	sum[1] = result[1];
}

/*
 * The basic idea is to break the 2 64-bit values into 4 32-bit values,
 * use native multiplication on those, and then re-combine into the
 * resulting 128-bit value.
 *
 * (hi1 << 32 + lo1) * (hi2 << 32 + lo2) =
 *     hi1 * hi2 << 64 +
 *     hi1 * lo2 << 32 +
 *     hi2 * lo1 << 32 +
 *     lo1 * lo2
 */
static inline void
dt_multiply_128(uint64_t factor1, uint64_t factor2, uint64_t *product)
{
	uint64_t hi1, hi2, lo1, lo2;
	uint64_t tmp[2];

	hi1 = factor1 >> 32;
	hi2 = factor2 >> 32;

	lo1 = factor1 & DT_MASK_LO;
	lo2 = factor2 & DT_MASK_LO;

	product[0] = lo1 * lo2;
	product[1] = hi1 * hi2;

	tmp[0] = hi1 * lo2;
	tmp[1] = 0;
	dt_shift_128(tmp, 32);
	dt_add_128(product, tmp, product);

	tmp[0] = hi2 * lo1;
	tmp[1] = 0;
	dt_shift_128(tmp, 32);
	dt_add_128(product, tmp, product);
}

/*
 * This is long-hand division.
 *
 * We initialize subtrahend by shifting divisor left as far as possible. We
 * loop, comparing subtrahend to dividend:  if subtrahend is smaller, we
 * subtract and set the appropriate bit in the result.  We then shift
 * subtrahend right by one bit for the next comparison.
 */
static inline void
dt_divide_128(uint64_t *dividend, uint64_t divisor, uint64_t *quotient)
{
	uint64_t result[2] = { 0, 0 };
	uint64_t remainder[2];
	uint64_t subtrahend[2];
	uint64_t divisor_128[2];
	uint64_t mask[2] = { 1, 0 };
	int log = 0;

	assert(divisor != 0);

	divisor_128[0] = divisor;
	divisor_128[1] = 0;

	remainder[0] = dividend[0];
	remainder[1] = dividend[1];

	subtrahend[0] = divisor;
	subtrahend[1] = 0;

	while (divisor > 0) {
		log++;
		divisor >>= 1;
	}

	dt_shift_128(subtrahend, 128 - log);
	dt_shift_128(mask, 128 - log);

	while (dt_ge_128(remainder, divisor_128)) {
		if (dt_ge_128(remainder, subtrahend)) {
			dt_subtract_128(remainder, subtrahend, remainder);
			result[0] |= mask[0];
			result[1] |= mask[1];
		}

		dt_shift_128(subtrahend, -1);
		dt_shift_128(mask, -1);
	}

	quotient[0] = result[0];
	quotient[1] = result[1];
}

/*
 * This is the long-hand method of calculating a square root.
 * The algorithm is as follows:
 *
 * 1. Group the digits by 2 from the right.
 * 2. Over the leftmost group, find the largest single-digit number
 *    whose square is less than that group.
 * 3. Subtract the result of the previous step (2 or 4, depending) and
 *    bring down the next two-digit group.
 * 4. For the result R we have so far, find the largest single-digit number
 *    x such that 2 * R * 10 * x + x^2 is less than the result from step 3.
 *    (Note that this is doubling R and performing a decimal left-shift by 1
 *    and searching for the appropriate decimal to fill the one's place.)
 *    The value x is the next digit in the square root.
 * Repeat steps 3 and 4 until the desired precision is reached.  (We're
 * dealing with integers, so the above is sufficient.)
 *
 * In decimal, the square root of 582,734 would be calculated as so:
 *
 *     __7__6__3
 *    | 58 27 34
 *     -49       (7^2 == 49 => 7 is the first digit in the square root)
 *      --
 *       9 27    (Subtract and bring down the next group.)
 * 146   8 76    (2 * 7 * 10 * 6 + 6^2 == 876 => 6 is the next digit in
 *      -----     the square root)
 *         51 34 (Subtract and bring down the next group.)
 * 1523    45 69 (2 * 76 * 10 * 3 + 3^2 == 4569 => 3 is the next digit in
 *         -----  the square root)
 *          5 65 (remainder)
 *
 * The above algorithm applies similarly in binary, but note that the
 * only possible non-zero value for x in step 4 is 1, so step 4 becomes a
 * simple decision: is 2 * R * 2 * 1 + 1^2 (aka R << 2 + 1) less than the
 * preceding difference?
 *
 * In binary, the square root of 11011011 would be calculated as so:
 *
 *     __1__1__1__0
 *    | 11 01 10 11
 *      01          (0 << 2 + 1 == 1 < 11 => this bit is 1)
 *      --
 *      10 01 10 11
 * 101   1 01       (1 << 2 + 1 == 101 < 1001 => next bit is 1)
 *      -----
 *       1 00 10 11
 * 1101    11 01    (11 << 2 + 1 == 1101 < 10010 => next bit is 1)
 *       -------
 *          1 01 11
 * 11101    1 11 01 (111 << 2 + 1 == 11101 > 10111 => last bit is 0)
 *
 */
static inline uint64_t
dt_sqrt_128(uint64_t *square)
{
	uint64_t result[2] = { 0, 0 };
	uint64_t diff[2] = { 0, 0 };
	uint64_t one[2] = { 1, 0 };
	uint64_t next_pair[2];
	uint64_t next_try[2];
	uint64_t bit_pairs, pair_shift;
	uint64_t i;

	bit_pairs = dt_nbits_128(square) / 2;
	pair_shift = bit_pairs * 2;

	for (i = 0; i <= bit_pairs; i++) {
		/*
		 * Bring down the next pair of bits.
		 */
		next_pair[0] = square[0];
		next_pair[1] = square[1];
		dt_shift_128(next_pair, -pair_shift);
		next_pair[0] &= 0x3;
		next_pair[1] = 0;

		dt_shift_128(diff, 2);
		dt_add_128(diff, next_pair, diff);

		/*
		 * next_try = R << 2 + 1
		 */
		next_try[0] = result[0];
		next_try[1] = result[1];
		dt_shift_128(next_try, 2);
		dt_add_128(next_try, one, next_try);

		if (dt_le_128(next_try, diff)) {
			dt_subtract_128(diff, next_try, diff);
			dt_shift_128(result, 1);
			dt_add_128(result, one, result);
		} else {
			dt_shift_128(result, 1);
		}

		pair_shift -= 2;
	}

	assert(result[1] == 0);

	return result[0];
}

static inline uint64_t
dt_stddev(uint64_t *data, uint64_t normal)
{
	uint64_t avg_of_squares[2];
	uint64_t square_of_avg[2];
	int64_t norm_avg;
	uint64_t diff[2];

	/*
	 * The standard approximation for standard deviation is
	 * sqrt(average(x**2) - average(x)**2), i.e. the square root
	 * of the average of the squares minus the square of the average.
	 */
	dt_divide_128(data + 2, normal, avg_of_squares);
	dt_divide_128(avg_of_squares, data[0], avg_of_squares);

	norm_avg = (int64_t)data[1] / (int64_t)normal / (int64_t)data[0];

	if (norm_avg < 0)
		norm_avg = -norm_avg;

	dt_multiply_128((uint64_t)norm_avg, (uint64_t)norm_avg, square_of_avg);

	dt_subtract_128(avg_of_squares, square_of_avg, diff);

	return dt_sqrt_128(diff);
}

#ifdef  __cplusplus
}
#endif

#endif	/* _DT_MATH_H */
