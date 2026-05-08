"""
Cryptographic Math Module
Supports modular arithmetic, prime generation, and multiplicative inverse functions
for encryption algorithms.
"""

import random


def gcd(a, b):
    """Calculate the Greatest Common Divisor using Euclidean algorithm"""
    while b:
        a, b = b, a % b
    return a


def extended_gcd(a, b):
    """
    Extended Euclidean Algorithm
    Returns (gcd, x, y) such that a*x + b*y = gcd(a, b)
    """
    if a == 0:
        return b, 0, 1
    
    gcd_val, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    
    return gcd_val, x, y


def mod_inverse(a, m):
    """
    Find modular multiplicative inverse of a under modulo m
    Returns x such that (a * x) % m = 1
    """
    gcd_val, x, _ = extended_gcd(a, m)
    
    if gcd_val != 1:
        raise ValueError(f"Modular inverse does not exist for {a} mod {m}")
    
    return (x % m + m) % m


def is_prime(n, k=5):
    """
    Miller-Rabin primality test
    k: number of rounds (higher = more accurate)
    """
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        
        if x == 1 or x == n - 1:
            continue
        
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    
    return True


def generate_prime(bits=16):
    """Generate a random prime number with specified bit length"""
    while True:
        candidate = random.getrandbits(bits)
        candidate |= 1
        candidate |= (1 << (bits - 1))
        
        if is_prime(candidate):
            return candidate


def power_mod(base, exponent, modulus):
    """
    Efficient modular exponentiation
    Computes (base^exponent) % modulus
    """
    result = 1
    base = base % modulus
    
    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulus
        exponent = exponent >> 1
        base = (base * base) % modulus
    
    return result


def find_primitive_root(p):
    """
    Find a primitive root (generator) modulo prime p
    A primitive root g generates all elements in Z*p
    """
    if p == 2:
        return 1
    
    phi = p - 1
    prime_factors = set()
    n = phi
    
    for i in range(2, int(n**0.5) + 1):
        while n % i == 0:
            prime_factors.add(i)
            n //= i
    if n > 1:
        prime_factors.add(n)
    
    for g in range(2, p):
        is_generator = True
        for factor in prime_factors:
            if power_mod(g, phi // factor, p) == 1:
                is_generator = False
                break
        
        if is_generator:
            return g
    
    return None
