def bit_ceil(x: int) -> int:
    """return the smallest integral power of 2 that is at least x"""
    if x <= 1:
        return 1
    return 1 << (x - 1).bit_length()


def get_bit(x: int, i: int) -> int:
    """return whether the ith bit of x is set"""
    return x >> i & 1


def get_bucket(x: int, level: int, num_levels: int) -> int:
    """implementation of $\mathcal P(x, \ell)$ from the paper
    finds the bucket at level l along the path P(x)

    if levels are labelled l = 0, 1, ..., num_levels-1
    and on level l the buckets are labelled 0, 1, ..., 2^l-1,
    then it follows that that parent of bucket i on level l is bucket i//2 on level l-1.

    Returns an integer which is the index of the bucket from left to right
    along the given level

    """
    assert 0 <= level < num_levels
    assert 0 <= x < (1 << (num_levels - 1))
    return x >> (num_levels - 1 - level)
