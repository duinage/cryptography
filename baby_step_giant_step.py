"""
The baby-step giant-step is a meet-in-the-middle algorithm for computing the discrete logarithm.
Author: Vadym Tunik.
"""

def dicrete_log(p: int, g: int, h: int) -> int:
    """ g^x = h (mod p) """
    order = p - 1
    m = int((order)**0.5) + 1 # ceil

    # baby step
    table = {pow(g, j, p): j for j in range(m)}

    # giant step
    precompute = pow(g, m*(p-2), p)
    for i in range(m):
        temp = (h*pow(precompute, i, p)) % p
        if temp in table:
            return i*m + table[temp]
    return None


if __name__=="__main__":
    # test
    print(f"{dicrete_log(23,5,3)=}") #should be 16
    