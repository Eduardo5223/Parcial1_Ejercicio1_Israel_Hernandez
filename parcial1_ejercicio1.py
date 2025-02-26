# Parcial 1
# Ejercicio 1
# Israel Hernandez

import Crypto.Random
import Crypto.Util.number 
from Crypto.Util.number import bytes_to_long, long_to_bytes
import hashlib
e = 65537

#ALice
pA = Crypto.Util.number.getPrime(1024, randfunc = Crypto.Random.get_random_bytes)
print('\n', 'RSA - Primo de Alice pA: ', pA)
qA = Crypto.Util.number.getPrime(1024, randfunc = Crypto.Random.get_random_bytes)
print('\n', 'RSA - Primo de Alice qA: ', qA)

#Bob
pB = Crypto.Util.number.getPrime(1024, randfunc = Crypto.Random.get_random_bytes)
print('\n', 'RSA - Primo de Bob pB: ', pB)
qB = Crypto.Util.number.getPrime(1024, randfunc = Crypto.Random.get_random_bytes)
print('\n', 'RSA - Primo de Bob qB: ', qB)

# Calculamos la llave publica de alice nA = pA * qA
nA = pA * qA

print('\n', 'RSA - nA: ', nA)

# Calcular la llave Privada de Alice
phiaA = (pA - 1) * (qA - 1)

dA = Crypto.Util.number.inverse(e, phiaA)

print('\n', 'Llave privada Alice dA: ', dA)

# Calculamos la llave publica de Bob nA = pA * qA
nB = pB * qB

print('\n', 'RSA - nB: ', nB)

# Calcular la llave Privada de Bob
phiaB = (pB - 1) * (qB - 1)

dB = Crypto.Util.number.inverse(e, phiaB)

print('\n', 'Llave privada Bob dB: ', dB)

# El mensaje a cifrar va a ser una cadena de 1050 caracteres
m = "El aprendizaje automático y la inteligencia artificial están transformando el mundo en el que vivimos. Desde la atención médica hasta la industria automotriz, estas tecnologías están revolucionando la forma en que interactuamos con el mundo. En el campo de la medicina, los algoritmos de IA pueden analizar grandes cantidades de datos médicos para predecir enfermedades y recomendar tratamientos personalizados. En la industria automotriz, los vehículos autónomos están utilizando sistemas de visión por computadora y aprendizaje profundo para navegar de manera segura en entornos complejos. Además, en el ámbito de las finanzas, los algoritmos de trading automatizados están tomando decisiones en milisegundos, aprovechando patrones en los datos que los humanos no podrían detectar. La IA también está teniendo un impacto significativo en la educación, donde los sistemas de tutoría inteligente pueden adaptarse a las necesidades individuales de los estudiantes, proporcionando una experiencia de aprendizaje personalizada. Sin embargo, llllllllllll"

print('La longitud de la cadena del mensaje es de: ',len(m), ' Caracteres')

hM = int.from_bytes(hashlib.sha256(m.encode('utf-8')).digest(), byteorder='big')
print("\n", "HASH de hM: ", hex(hM))

#Longitud del mensaje
print(len(m))

#Separamos el mensaje en partes de a 128 caracteres y convertimos a bytes
mensaje = []

for i in range(0,len(m), 128):
    mensaje.append(m[i:i + 128].encode('utf-8'))

#Creamos una lista donde ira el mensaje cifrado
mensaje_cifrado=[]

# Alice cifra el mensaje con la clave unica de Bob, convertimos los bytes a enteros y los metemos a la formurmula, despues los regresamos a bytes
for i in mensaje:
    mensaje_numero = bytes_to_long(i)
    mc = pow(mensaje_numero, e, nB)
    mensaje_cifrado.append(long_to_bytes(mc))

# Bob descifra el mensaje con su clave privada
mensaje_descifrado = []

for i in mensaje_cifrado:
    mensaje_cifrado_numero = bytes_to_long(i)
    md = pow(mensaje_cifrado_numero, dB, nB)
    mensaje_descifrado.append(long_to_bytes(md).decode('utf-8'))

mensaje_final = ""
for i in mensaje_descifrado:
    mensaje_final = mensaje_final + i

hM1 = int.from_bytes(hashlib.sha256(mensaje_final.encode('utf-8')).digest(), byteorder='big')
print("\n", "HASH de hM: ", hex(hM1))

if hM == hM1:
    print("El mensaje fue entregado con exito sin alteraciones")
else:
    print("El mensaje sufrio alguna alteracion")







