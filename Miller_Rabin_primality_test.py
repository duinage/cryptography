"""
The Miller-Rabin primality test: an algorithm which determines whether a given number is prime or not.
Author: Vadym Tunik.
"""
from random import randint


def miller_rabin_test(n: int, k: int = 10, show_generation_of_a: bool = False) -> bool:
    """ 
    The function determines whether the given number "n" is prime with probability 1/4^k.
    
    Args:
        n: number to check
        k: amount of rounds
        show_generation_of_a: a toggle switch that enables the output of the history of generating a random witness "a".
    Return:
        True: the given number "n" is prime with probability 1/4^k.
        False: the given number "n" is composite.
    """
    assert n>2, "Wrong input!"
    assert isinstance(n,int), "Wrong input!"

    if n%2==0:
        return False
    
    # n-1 = 2^s * d
    s, d = 0, n-1
    while d%2==0:
        s += 1
        d //= 2

    for i in range(k):
        a = randint(2, n-1) # random witness from [2, n-1]
        if show_generation_of_a: print(f"test n.{i}, {a=}")

        x = pow(base=a, exp=d, mod=n)
        
        if x == 1 or x == n-1: continue

        for _ in range(s-1):
            x = pow(x, 2, n)
            if x == 1: return False
            if x == n-1: break
        else:
            return False
    
    return True



if __name__=='__main__':
    from sympy import randprime
    test_number = randprime(2**511, 2**512)
    test_result = miller_rabin_test(test_number, k=100, show_generation_of_a=True)
    if test_result:
        print(f"{test_number=}\nis probably a prime number.")
    else:
        print(f"{test_number=}\nis composite number.")