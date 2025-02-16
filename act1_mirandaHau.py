import hashlib
import random

# Número primo estándar para Diffie-Hellman
p = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF", 16)
g = 2

print("\n*****************************")
print("\nVariables Públicas Compartidas")
print("\nNúmero primo compartido públicamente RFC 3625:", p)
print("\nNúmero base compartido públicamente:", g)

# Generar claves privadas
sAlice = random.getrandbits(256)
sBob = random.getrandbits(256)
sEve = random.getrandbits(256)

print("\nNúmero privado de Alice:", sAlice)
print("\nNúmero privado de Bob:", sBob)
print("\nNúmero privado de Eve:", sEve)

# Alice y Bob generan sus valores públicos
A = pow(g, sAlice, p)
B = pow(g, sBob, p)

print("\nMensaje de Alice (valor público A):", A)
print("\nMensaje de Bob (valor público B):", B)

# Eve intercepta y genera valores falsos
EveA = pow(g, sEve, p)  # Valor falso que Eve envía a Bob
EveB = pow(g, sEve, p)  # Valor falso que Eve envía a Alice

# Alice y Bob calculan la clave secreta con los valores interceptados por Eve
shared_Alice_Eve = pow(EveB, sAlice, p)
shared_Bob_Eve = pow(EveA, sBob, p)

print("\nLlave secreta compartida (Alice - Eve):", shared_Alice_Eve)
print("\nLlave secreta compartida (Bob - Eve):", shared_Bob_Eve)

# Eve calcula las claves robadas correctamente
shared_Eve_Alice = pow(A, sEve, p)
shared_Eve_Bob = pow(B, sEve, p)

print("\nLlave secreta robada (Eve con Alice):", shared_Eve_Alice)
print("\nLlave secreta robada (Eve con Bob):", shared_Eve_Bob)

# Aplicar función hash a las llaves obtenidas
h1 = hashlib.sha512(int.to_bytes(shared_Alice_Eve, length=1024, byteorder="big")).hexdigest()
h2 = hashlib.sha512(int.to_bytes(shared_Bob_Eve, length=1024, byteorder="big")).hexdigest()

if h1 == h2:
    print("\nMITM exitoso: Alice y Bob tienen la misma clave interceptada por Eve\n")
else:
    print("\nFallo en el ataque MITM: las claves no coinciden\n")

# Eve verifica si logró interceptar con éxito
h3 = hashlib.sha512(int.to_bytes(shared_Eve_Alice, length=1024, byteorder="big")).hexdigest()
h4 = hashlib.sha512(int.to_bytes(shared_Eve_Bob, length=1024, byteorder="big")).hexdigest()

if h3 == h4:
    print("\nEve logró descifrar el mensaje de Alice y Bob con éxito!\n")
else:
    print("\nEve falló en el ataque y no obtuvo la misma clave secreta\n")
