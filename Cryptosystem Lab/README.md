# RSA Cryptosystem Challenge — Write-Up

## Overview

This challenge involved breaking a poorly implemented RSA cryptosystem. The goal was to recover the secret flag by exploiting a weakness in how the primes were generated.

---

## Key Insight

The vulnerability lies in this line:

```python
q = primo(p)
```

Where `primo(p)` returns the **next prime after `p`**.

### Why this is insecure:

* In RSA, `p` and `q` should be **random and far apart**
* Here, `q ≈ p`
* This makes the modulus:

[
n = p \cdot q \approx p^2
]

This violates RSA security assumptions and enables **Fermat Factorization**

---

## Given Values

We are provided with:

* `n` → RSA modulus
* `e = 65537` → public exponent
* `c` → ciphertext

---

## Attack Strategy — Fermat Factorization

### Step 1: Use the identity

[
n = a^2 - b^2 = (a - b)(a + b)
]

If `p` and `q` are close:

* ( a \approx \sqrt{n} )
* ( b^2 = a^2 - n )

---

### Step 2: Compute `a`

[
a = \lceil \sqrt{n} \rceil
]

---

### Step 3: Iterate until perfect square

We compute:

[
b^2 = a^2 - n
]

Check if ( b^2 ) is a perfect square:

* If yes:

  * ( p = a - b )
  * ( q = a + b )

---

## Full Exploit Code

```python
from Crypto.Util.number import *
import math

n = 15956250162063169819282947443743274370048643274416742655348817823973383829364700573954709256391245826513107784713930378963551647706777479778285473302665664446406061485616884195924631582130633137574953293367927991283669562895956699807156958071540818023122362163066253240925121801013767660074748021238790391454429710804497432783852601549399523002968004989537717283440868312648042676103745061431799927120153523260328285953425136675794192604406865878795209326998767174918642599709728617452705492122243853548109914399185369813289827342294084203933615645390728890698153490318636544474714700796569746488209438597446475170891

c = 3591116664311986976882299385598135447435246460706500887241769555088416359682787844532414943573794993699976035504884662834956846849863199643104254423886040489307177240200877443325036469020737734735252009890203860703565467027494906178455257487560902599823364571072627673274663460167258994444999732164163413069705603918912918029341906731249618390560631294516460072060282096338188363218018310558256333502075481132593474784272529318141983016684762611853350058135420177436511646593703541994904632405891675848987355444490338162636360806437862679321612136147437578799696630631933277767263530526354532898655937702383789647510

e = 65537

# Step 1: Start at sqrt(n)
a = math.isqrt(n)
if a * a < n:
    a += 1

# Step 2: Fermat factorization loop
while True:
    b2 = a*a - n
    b = math.isqrt(b2)
    if b*b == b2:
        p = a - b
        q = a + b
        break
    a += 1

# Step 3: Compute phi(n)
phi = (p-1)*(q-1)

# Step 4: Compute private key
d = inverse(e, phi)

# Step 5: Decrypt ciphertext
m = pow(c, d, n)

# Step 6: Convert to readable flag
print(long_to_bytes(m))
```

---

## Decryption Process Explained

1. Factor `n` → recover `p` and `q`
2. Compute:

[
\phi(n) = (p-1)(q-1)
]

3. Compute private exponent:

[
d = e^{-1} \mod \phi(n)
]

4. Decrypt:

[
m = c^d \mod n
]

5. Convert integer → bytes → readable flag

---

## Why This Works

Fermat factorization is efficient when:

[
|p - q| \text{ is small}
]

Since:

* `q = nextPrime(p)`
* The gap is extremely small

This makes factorization **fast instead of computationally infeasible**

---

## Lessons Learned

* RSA security depends heavily on **random, well-separated primes**
* Poor prime selection leads to catastrophic failure
* Fermat’s method is a powerful attack in edge cases
* Always verify cryptographic assumptions in implementations

---

## Final Result

* Successfully factored `n`
* Recovered private key `d`
* Decrypted ciphertext
* Retrieved the original flag

---

## Summary

| Step | Action                         |
| ---- | ------------------------------ |
| 1    | Identify weak prime generation |
| 2    | Apply Fermat factorization     |
| 3    | Recover `p` and `q`            |
| 4    | Compute `d`                    |
| 5    | Decrypt `c`                    |
| 6    | Extract flag                   |

---

This challenge demonstrates how a **small implementation flaw completely breaks RSA security**.
