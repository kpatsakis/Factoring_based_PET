import base64
from time import time
from hashlib import sha256
from Crypto import Random
from Crypto.Cipher import AES

class AESCipher(object):

    def __init__(self, key):
        self.BS = AES.block_size
        try:
            self.key = sha256(key.encode('ISO-8859-1')).digest()[:self.BS]
        except:
            self.key = sha256(key).digest()[:self.BS]
        self.iv = Random.new().read(AES.block_size)
    def encrypt(self, raw):
        raw = self._pad(raw)
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        return base64.b64encode(self.iv + cipher.encrypt(raw))
    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        self.iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('ISO-8859-1')
    def _pad(self, s):
        return s + (self.BS - len(s) % self.BS) * chr(self.BS - len(s) % self.BS).encode('ISO-8859-1')
    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]


#curve y**2=x**3+a*x+b

SEC=128

if SEC==128:
	# Curve25519 y^2=x^3+ax^2+x
	a=486662
	p=2^255-19
	F = Zmod(p)
	E = EllipticCurve([F(0), F(a), F(0), F(1), F(0)])
	x0=9
	y0=E.lift_x(x0)[1]
elif SEC==192:
	#M-383 	y^2 = x^3+2065150x^2+x
	#Aranha–Barreto–Pereira–Ricardini
	p = 2^383 - 187
	F = Zmod(p)
	E = EllipticCurve([F(0), F(2065150), F(0), F(1), F(0)])
	x0=12
	y0=E.lift_x(x0)[1]
else:
	#M-511 y^2 = x^3+530438x^2+x
	#Aranha–Barreto–Pereira–Ricardini
	p = 2^511 - 187
	F = Zmod(p)
	E = EllipticCurve([F(0), F(530438), F(0), F(1), F(0)])
	x0=5
	y0=E.lift_x(x0)[1]

P = E([x0,y0])
k=ZZ.random_element(p)
H=k*P
TOTAL_TESTS=100
tA=0
tB=0

for i in range(TOTAL_TESTS):
	#alice
	ts=time()
	lA=ZZ.random_element(2**32)*P
	ra=ZZ.random_element(p)
	A=ra*lA
	tA+=time()-ts

	#Bob
	ts=time()
	lB=ZZ.random_element(2**32)*P
	rb=ZZ.random_element(p)
	B=rb*lB
	kb=sha256(str(rb*A)).hexdigest()
	hb=sha256(str(A)+str(B)).hexdigest()
	aesBob=AESCipher(kb)
	cb=aesBob.encrypt(hb)
	tB+=time()-ts

	#Alice check
	ts=time()
	ka=sha256(str(ra*B)).hexdigest()
	aesAlice=AESCipher(ka)
	hbb=aesAlice.decrypt(cb)
	ha=sha256(str(A)+str(B)).hexdigest()
	comp=hbb==ha
	tA+=time()-ts

print "Alice average:",tA/TOTAL_TESTS
print "Bob average:",tB/TOTAL_TESTS
