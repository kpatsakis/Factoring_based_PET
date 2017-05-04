import hashlib
from time import time
def gen_prime(BITS):
    lb=2**(BITS-1)
    ub=2*lb
    return random_prime(ub,False,lb)

def gen_safe_prime(BITS):
    qq=1
    while not qq.is_prime():
        pp=gen_prime(BITS-1)
        qq=2*pp+1
    return qq

def RSA_KEY_GEN(BITS):
    p=gen_safe_prime(BITS)
    q=gen_safe_prime(BITS)
    N=p*q
    fi=(p-1)*(q-1)
    e=2**16+1
    d=inverse_mod(e,fi)
    dp=inverse_mod(e,p-1)
    dq=inverse_mod(e,q-1)
    qInv = inverse_mod(q,p)

    return p,q,e,d,dp,dq,qInv,N,fi

def RSA_Encrypt(m,e,n):
    return pow(m,e,N)
def RSA_Decrypt(c,p,q,d,dp,dq,qInv,N):
    m1=int(pow(c, dp,p))
    m2=int(pow(c, dq,q))
    h = (qInv * (m1 - m2)) % p
    return (m2 + h * q)%N

BITS=512
print "Please wait, generating parameters..."
p,q,e,d,dp,dq,qInv,N,fi=RSA_KEY_GEN(BITS)
print "Done! Running tests now..."
tA=0
tB=0
TESTS=100
for i in range(TESTS):
    ###Alice
    ts=time()
    lA=2*ZZ.random_element(2**31)+1
    rA=ZZ.random_element(N)
    #select a random location
    cA=pow(rA,lA,N)
    tA+=time()-ts
    ###Bob
    ts=time()
    lB=2*ZZ.random_element(2**31)+1
    e_B=inverse_mod(lA,fi)
    tmp=pow(cA,e_B,N)
    res=hashlib.sha224(str(tmp)).hexdigest()
    tB+=time()-ts
    ###Alice
    ts=time()
    comp= (res==hashlib.sha224(str(rA)).hexdigest())
    tA+=time()-ts

print "Average times:\nAlice:%0.5f\nBob:%0.5f"%(tA/TESTS,tB/TESTS)
