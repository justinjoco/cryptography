#!usr/bin/env python2.7
'''
Justin-Anthony Joco
ECE 404 HW 06
jjoco
02/22/2018

'''
import sys
from BitVector import *
from PrimeGenerator import *


BLOCKSIZE = 128
E_BLOCKSIZE = 256
BYTE_SIZE = 8


'''
Implementation of Python's pow function used in lecture
Efficiently calculates A^B mod n
'''
def mod_pow(A, B, n):
	
	result = 1
	while (B >0):
		if B & 1:
			result = (result  * A)% n
		B = B >> 1
		A = (A * A) %n

	return result


'''
Returns the greatest common denominator of a and b
'''
def gcd(a,b):

	while b:
		a,b = b, a%b

	return a

'''
Generates 128-bit prime factors, p and q
This ensures p and q are not equal, and each is coprime with e
'''
def generate_p_q(e, num_bits_desired):

	p = 0
	q = 0
	generator = PrimeGenerator(bits = num_bits_desired)
	
	while (p == q):
		p = generator.findPrime()
		q = generator.findPrime()
	
		while(gcd(p-1, e)!=1):
			p = generator.findPrime()
	
		while(gcd(q-1, e)!= 1):
			q = generator.findPrime()

	return p, q


'''
Given encryption integer and prime factors, p and q,
this function generates the private key using the following eq:
d = e^-1 mod phi_n, in which phi_n = (p-1)*(q-1)
'''

def generate_private_key(e, p, q):
	totient_n_bv = BitVector(intVal = (p-1)*(q-1))
	e_bv = BitVector(intVal = e)
	d_bv = e_bv.multiplicative_inverse(totient_n_bv)
	return d_bv.int_val()



'''
Returns the right half of 256-bit recovered block. 
If decryption was done correctly, the left half should be made up of zero bits only
'''
def remove_padding(recovered_bv_block):

	[zero_bv, content_bv] = recovered_bv_block.divide_into_two()
	return content_bv

'''
Removes the newlines padded in the recovered plaintext
'''
def remove_newlines(recovered_bv):

	newline_bv = BitVector(textstring = "\n")

	for i in range(len(recovered_bv)// BYTE_SIZE-1, -1, -1):
		bv = recovered_bv[i*BYTE_SIZE:(i+1)*BYTE_SIZE]
		if (bv!=newline_bv):
			break
		recovered_bv = recovered_bv[:(i+1)*BYTE_SIZE]
	return recovered_bv

'''
Generates values necessary for efficient decryption 
using the Chinese Remainder Theorem
'''
def generate_CRT_vals(C_int, d, p, q):

	#Vp = C^d mod p
	#Vq = C^d mod q
	Vp = mod_pow(C_int, d, p)
	Vq = mod_pow(C_int, d, q)

	q_bv = BitVector(intVal = q)
	p_bv = BitVector(intVal = p)

	inv_q_mod_p = q_bv.multiplicative_inverse(p_bv)
	inv_p_mod_q = p_bv.multiplicative_inverse(q_bv)

	#Xp = q*(q^-1 mod p)
	#Xq = p*(p^-1 mod q)
	Xp = q * inv_q_mod_p.int_val()
	Xq = p * inv_p_mod_q.int_val()


	return Vp, Vq, Xp, Xq

'''
Given encryption integer and number n, this function reads
an plaintext file and encrypts it using RSA
'''

def encrypt(message_path, e, n):

	#Opens message file and calculates the message's bitlength and required padding
	message_file = open(message_path)
	message_string = message_file.read()
	message_bitlength = len(message_string)*BYTE_SIZE
	padding = BLOCKSIZE - message_bitlength%BLOCKSIZE

	#Pads the message string with newlines if the message's bitlength is not a multiple of 128
	if (padding!=BLOCKSIZE):
		num_newlines = padding//BYTE_SIZE
		for i in range(0, num_newlines):
			message_string+="\n"

	#Intializes message and output bitvectors
	message_bv = BitVector(textstring = message_string)
	output_bv = BitVector(size = 0)

	#Prepends 128-bit data block with 128 zeros
	#Expresses message bv into integer M
	#Encryption follows eq: C = M^e mod n
	#Encrypted block is concatenated to output_bv
	for i in range(0, len(message_bv) // BLOCKSIZE):
		bitvec = message_bv[i*BLOCKSIZE:(i+1)*BLOCKSIZE]
		bitvec.pad_from_left(BLOCKSIZE)
		message_int = bitvec.int_val()
		result = mod_pow(message_int, e, n)
		bitvec.set_value(intVal = result, size = 256)
		output_bv+=bitvec
	
	
	return output_bv.get_bitvector_in_hex()

'''
Given decryption integer and prime factors (p and q) of n, this function
reads an encrypted file and returns the recovered text in hex and ascii
'''

def decrypt(encrypted_path, d, p , q):
	
	#Initializes variables
	encrypted_file = open(encrypted_path)
	encrypted_bv = BitVector(hexstring = encrypted_file.read())
	n = p*q
	recovered = BitVector(size = 0)


	#Iterates through encrypted data in blocks of 256
	#Calculates plaintext block using M = C^d mod n = (Vp*Xp + Vq*Xq) mod n
	#Recovered block is shortened back into 128 and added to overall recovered text bv
	for i in range(0, len(encrypted_bv) // E_BLOCKSIZE):
		bitvec = encrypted_bv[i*E_BLOCKSIZE:(i+1)*E_BLOCKSIZE] 
		C_int = bitvec.int_val()
		[Vp, Vq, Xp, Xq] = generate_CRT_vals(C_int, d, p, q)
		temp_result_int = (Vp*Xp + Vq*Xq)%n
		temp_bv = BitVector(intVal = temp_result_int, size = E_BLOCKSIZE)
		shortened_bv = remove_padding(temp_bv)
		recovered += shortened_bv

	#Removes extra newline paddings in order to be readable
	recovered = remove_newlines(recovered)

	#Returns the recovered text in hex and ascii
	return recovered.get_bitvector_in_hex(), recovered.get_bitvector_in_ascii()

#Writes encryption integer and modulus n to file
def write_public_key_to_file(public_path, e,n):
	mod_file = open(public_path, "w")
	mod_file.write(str(e))
	mod_file.write("\n")
	mod_file.write(str(n))
	mod_file.close()
	return

#Writes decryption integer and prime factors p and q to file
def write_private_key_to_file(private_path, d, p, q):

	mod_file = open(private_path, "w")
	mod_file.write(str(d))
	mod_file.write("\n")
	mod_file.write(str(p))
	mod_file.write("\n")
	mod_file.write(str(q))
	mod_file.close()

	return

#Wrapper function that encrypts input file, writes ciphertext to file, and returns the public key
def rsa_encrypt(message_path, encrypted_path, e, n):
	
	ciphertext = encrypt(message_path, e, n)
	encrypted_file = open(encrypted_path, "w")
	encrypted_file.write(ciphertext)
	encrypted_file.close()

	return e, n

#Wrapper function that decrypts input file, writes recovered text to files in hex and ascii, and returns the private key
def rsa_decrypt(encrypted_path, hex_path, ascii_path, d, p, q):

	recovered_hex, recovered_ascii = decrypt(encrypted_path, d, p, q)
	ascii_file = open(ascii_path, "w")
	ascii_file.write(recovered_ascii)
	ascii_file.close()
	
	hex_file = open(hex_path, "w")
	hex_file.write(recovered_hex)
	hex_file.close()


	return d, p, q

#Given encryption integer and desired size of p and q,
#this returns decryption integer d, and prime factors p and q
def generate_keys(e, desired_bit_number):
	p, q = generate_p_q(e, desired_bit_number)
	d = generate_private_key (e, p, q)
	return d, p, q

def main():

	if (len(sys.argv) != 4):
		print("You need to have arguments in this order: encrypt/decrypt mode, input text file, output text file")
		sys.exit()
	
	mode = sys.argv[1]
	input_path = sys.argv[2]
	output_path = sys.argv[3]
	
	e = 65537
	
	#In encryption mode, this generates the public and private keys and prints them to different files
	#This also encrypts the message file with e and n=p*q
	if (mode == "-e"):
		
		d, p, q = generate_keys(e, 128)
		write_public_key_to_file("public_key.txt", e, p*q)
		write_private_key_to_file("private_key.txt", d, p, q)
		rsa_encrypt(input_path, output_path, e, p*q)
		
		
	#In decryption mode, this reads the private key file and decrypts input encrypted file using the read private key
	elif(mode == "-d"):
		try:
			mod_file = open("private_key.txt", "r")
			d = int(mod_file.readline())
			p = int(mod_file.readline())
			q = int(mod_file.readline())

		except:
			print("<mod>.txt needs to exist. Encrypt before decrypting")
			sys.exit()

		rsa_decrypt(input_path, output_path[:-4]+"_hex.txt" , output_path, d, p, q)
	
	#In case -e or -d was not entered
	else:
		print("Invalid mode")

	

if __name__ == "__main__":
	main()
