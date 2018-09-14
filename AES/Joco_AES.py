#!usr/bin/env python2.7

import sys
import time
from BitVector import *
from collections import deque
import copy

'''
Initialize constants and lists
'''
KEY_SIZE = 128
BLOCKSIZE = 128
NUM_ROUNDS = 10
BYTE_SIZE = 8
AES_modulus = BitVector(bitstring='100011011')
subBytesTable = []
invSubBytesTable = []

'''
Implements shifting process given a state array
'''
def shiftStateArray(stateArray):		
	for i in range(0, 4):
		temp = stateArray[i]
		temp_deque = deque(temp)
		temp_deque.rotate(-i)
		stateArray[i] = list(temp_deque)

	return stateArray

'''
Implements inverse shifting process given a state array
'''
def invShift(stateArray):

	for i in range(0,4):

		temp = stateArray[i]
		temp_deque = deque(temp)
		temp_deque.rotate(i)
		stateArray[i] = list(temp_deque)

	return stateArray


'''
Converts a bitvector block into a 4x4 state array
'''
def blockToStateArray(block):
	statearray = [[None for x in range(4)] for x in range(4)]
	BYTE_SIZE = 8
	count = 0
	for i in range(4):
		for j in range(4):
			statearray[j][i] = block[count*BYTE_SIZE:(count+1)*BYTE_SIZE]
			count+=1


	return statearray


'''
Converts a 4x4 state array into a bitvector block
'''
def stateArrayToBlock(stateArray):
	output = BitVector(size = 0)

	for i in range(4):
		for j in range(4):
			output+=stateArray[j][i]


	return output



'''
Creates lookup table for substitution step
'''

def genEncryptTable():
	c = BitVector(bitstring='01100011')
	for i in range(0, 256):
		# For the encryption SBox
		a = BitVector(intVal = i, size=8).gf_MI(AES_modulus, 8) if i != 0 else BitVector(intVal=0)
		# For bit scrambling for the encryption SBox entries:
		a1,a2,a3,a4 = [a.deep_copy() for x in range(4)]
		a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
		subBytesTable.append(int(a))

'''
Creates lookup table for inverse substitute step
'''
def genDecryptTable():
	d = BitVector(bitstring='00000101')
	for i in range(0,256):
		# For the decryption Sbox:
		b = BitVector(intVal = i, size=8)
		# For bit scrambling for the decryption SBox entries:
		b1,b2,b3 = [b.deep_copy() for x in range(3)]
		b = (b1 >> 2) ^ (b2 >> 5) ^ (b3 >> 7) ^ d
		check = b.gf_MI(AES_modulus, 8)
		b = check if isinstance(check, BitVector) else 0
		invSubBytesTable.append(int(b))


def gen_key_schedule_128(key_bv):
	key_words = [None for i in range(44)]
	round_constant = BitVector(intVal = 0x01, size=8)
	for i in range(4):
		key_words[i] = key_bv[i*32: i*32+32]
	for i in range(4,44):
		if i%4 == 0:
			kwd, round_constant = gee(key_words[i-1], round_constant, subBytesTable)
			key_words[i] = key_words[i-4] ^ kwd
		else:
			key_words[i] = key_words[i-4] ^ key_words[i-1]
	return key_words


def gee(keyword, round_constant, byte_sub_table):

	rotated_word = keyword.deep_copy()
	rotated_word << 8
	new_word = BitVector(size = 0)
	for i in range(4):
		new_word +=BitVector(intVal = subBytesTable[rotated_word[i*8:(i+1)*8].intValue()], size = 8)
	new_word[:8]^=round_constant
	round_constant = round_constant.gf_multiply_modular(BitVector(intVal = 0x02), AES_modulus, 8)
	return new_word, round_constant

'''
Utility function to see the elements within state array
'''
def print_state_array(stateArray, old_or_new):

	print("{}".format(old_or_new))
	for i in range(4):
		for j in range(4):
			print ("({}, {}) = {}".format(i,j, stateArray[i][j].get_bitvector_in_hex())),
		print('')

	return
'''
Substitutes bytes within a block based on s_box lookup table
'''
def sub_bytes(bv_block):
	
	output = BitVector(size = 0)
	for i in range(0, len(bv_block)//8):
		temp = bv_block[i*8:(i+1)*8]
		new_value = subBytesTable[temp.int_val()]
		new_temp = BitVector(intVal = new_value, size = 8)
		output+=new_temp

	return output
'''
Substitutes bytes within a block based on inverse s_box lookup table
'''
def inv_sub_bytes(bv_block):
	output = BitVector(size = 0)
	for i in range(0, len(bv_block) // 8):
		temp = bv_block[i*8:(i+1)*8]
		new_value = invSubBytesTable[temp.int_val()]
		new_temp = BitVector(intVal = new_value, size = 8)
		output+=new_temp

	return output


'''
Shifts state array rows
Row 0: No shift
Row 1: 1 shift left
Row 2: 2 shifts left
Row 3: 3 shifts left
'''
def shift_rows(bv_block):
	stateArray = blockToStateArray(bv_block)
	new_array = shiftStateArray(stateArray)
	ret_block = stateArrayToBlock(new_array)
	return ret_block


'''
Shifts state array rows inversely to shift_rows
Row 0: No shift
Row 1: 1 right shift
Row 2: 2 right shifts
Row 3: 3 right shifts
'''
def inv_shift_rows(bv_block):
	stateArray = blockToStateArray(bv_block)
	inv_shift_array = invShift(stateArray)
	ret_block = stateArrayToBlock(inv_shift_array)
	return ret_block


'''
Utility function to create a state array based on integer values from BitVectors
'''
def convertBitArrayToIntArray(bit_array):
	intArray = [[None for x in range(4)] for x in range(4)]

	for i in range(4):
		for j in range(4):
			intArray[i][j] = bit_array[i][j].int_val()

	return intArray

'''
Replaces each byte a column by a function of all bytes in the same column
'''
def mix_cols(bv_block):
	stateArray = blockToStateArray(bv_block)
	
	#Need a deep copy to have a constant reference for processing 
	temp = copy.deepcopy(stateArray)

	O2_bv = BitVector(intVal = 0x02)
	O3_bv = BitVector(intVal = 0x03)
	n = 8
	for j in range(4):
		stateArray[0][j] = (O2_bv.gf_multiply_modular(temp[0][j], AES_modulus, n)) ^ (O3_bv.gf_multiply_modular(temp[1][j], AES_modulus, n)) ^ temp[2][j] ^ temp[3][j]
		stateArray[1][j] = temp[0][j] ^ (O2_bv.gf_multiply_modular(temp[1][j], AES_modulus, n)) ^ (O3_bv.gf_multiply_modular(temp[2][j],AES_modulus, n)) ^ temp[3][j]

		stateArray[2][j] = temp[0][j] ^ temp[1][j] ^ (O2_bv.gf_multiply_modular(temp[2][j], AES_modulus, n)) ^ (O3_bv.gf_multiply_modular(temp[3][j], AES_modulus, n))
		
		stateArray[3][j] = (O3_bv.gf_multiply_modular(temp[0][j], AES_modulus, n)) ^ temp[1][j] ^ temp[2][j] ^ (O2_bv.gf_multiply_modular(temp[3][j], AES_modulus, n))


	output = stateArrayToBlock(stateArray)
	return output


'''
Computes recovered state array based on inverse mix_column matrix and current state array
'''
def inv_mix_cols(bv_block):

	stateArray = blockToStateArray(bv_block)
	
	temp = copy.deepcopy(stateArray)
	OE_bv = BitVector(intVal = 0x0E)
	OB_bv = BitVector(intVal = 0x0B)
	OD_bv = BitVector(intVal = 0x0D)
	O9_bv = BitVector(intVal = 0x09)

	n = 8

	for j in range(4):
		stateArray[0][j] = (OE_bv.gf_multiply_modular(temp[0][j], AES_modulus, n)) ^ (OB_bv.gf_multiply_modular(temp[1][j], AES_modulus, n)) ^ (OD_bv.gf_multiply_modular(temp[2][j],AES_modulus, n)) ^ (O9_bv.gf_multiply_modular(temp[3][j], AES_modulus, n))

		stateArray[1][j] = (O9_bv.gf_multiply_modular(temp[0][j], AES_modulus, n)) ^ (OE_bv.gf_multiply_modular(temp[1][j], AES_modulus, n)) ^ (OB_bv.gf_multiply_modular(temp[2][j],AES_modulus, n)) ^ (OD_bv.gf_multiply_modular(temp[3][j], AES_modulus, n))
		stateArray[2][j] = (OD_bv.gf_multiply_modular(temp[0][j], AES_modulus, n)) ^ (O9_bv.gf_multiply_modular(temp[1][j], AES_modulus, n)) ^ (OE_bv.gf_multiply_modular(temp[2][j],AES_modulus, n)) ^ (OB_bv.gf_multiply_modular(temp[3][j    ], AES_modulus, n))
		stateArray[3][j] = (OB_bv.gf_multiply_modular(temp[0][j], AES_modulus, n)) ^ (OD_bv.gf_multiply_modular(temp[1][j], AES_modulus, n)) ^ (O9_bv.gf_multiply_modular(temp[2][j],AES_modulus, n)) ^ (OE_bv.gf_multiply_modular(temp[3][j    ], AES_modulus, n))

	output = stateArrayToBlock(stateArray)
	return output

def add_round_key(bv_block, round_key):
	return bv_block ^ round_key


'''
Constructs round key list by concatenating 4 words within key_words list
'''
def gen_round_keys(key_bv):
	key_words = gen_key_schedule_128(key_bv)
	round_keys = []
	for i in range(0,NUM_ROUNDS +1):
		round_key = key_words[i] + key_words[i+1] + key_words[i+2] + key_words[i+3]
		round_keys.append(round_key)
	
	return round_keys


'''
Slices off last bytes of the recovered_bv if those bytes have '00000000' bitstrings
'''
def remove_padding(recovered_bv):

	zero_bv = BitVector(bitstring = '00000000')

	for i in range(len(recovered_bv)//BYTE_SIZE -1, -1, -1):
		bv = recovered_bv[i*BYTE_SIZE:(i+1)*BYTE_SIZE]
		if (bv != zero_bv):
			break
		recovered_bv = recovered_bv[:i*BYTE_SIZE]
	
	return recovered_bv

'''
Encrypts plaintext using AES Encryption and returns the ciphertext in hexidecimal
'''
def encrypt(message_path, key):
	key_bv = BitVector(textstring = key)
	message_file = open(message_path)
	message_bv = BitVector(textstring = message_file.read())	

	#Creates global encryption s_box
	genEncryptTable()

	#Generates round keys
	round_keys=gen_round_keys(key_bv)

	#Initializes previous block
	previous_block = message_bv

	#Pads the end of message bitvector if its length is not divisble by 128 
	padding = 128-len(previous_block)%128
	if (padding != 128):
		previous_block.pad_from_right(padding)	
	

	round_count = 0
	
	#Iterates through the round keys
	for round_key in round_keys:

		temp = BitVector(size = 0)
		#Iterates through 128-bit blocks of text
		for i in range(0, len(message_bv) // BLOCKSIZE):
			bitvec = previous_block[i*BLOCKSIZE:(i+1)*BLOCKSIZE]

			'''
			-> Substitute bytes according to lookup table (Occurs every round)
			-> Shift Rows in state array (Occurs every round)
			-> Mix Columns in state array (Doesn't happen in last round)
			-> Addround key (Occurs every round and before round 1) 
			'''
			if (round_count>0):
				bitvec = sub_bytes(bitvec)
				bitvec = shift_rows(bitvec)
				if (round_count<NUM_ROUNDS):
					bitvec = mix_cols(bitvec)
			bitvec = add_round_key(bitvec, round_key)
			temp+=bitvec

		#Saves changed block for next round
		previous_block = temp
		round_count +=1

	#Saves changed bitvector into an output bitvector
	output = previous_block
	
	return output.get_bitvector_in_hex()

'''
Decrypts ciphertext using AES Decryption and returns recovered text as an ascii string
'''
def decrypt(encrypted_path, key):
	key_bv = BitVector(textstring = key)
	encrypted_file = open(encrypted_path)
	encrypted_bv = BitVector(hexstring = encrypted_file.read())
	
	#Generates s_box for inverse substitution step
	genDecryptTable()
	
	#Generates round keys
	round_keys = gen_round_keys(key_bv)
	previous_block = encrypted_bv

	#Adds padding if necessary
	padding = BLOCKSIZE - len(previous_block)%BLOCKSIZE
	if (padding != 128):
		previous_block.pad_from_right(padding)

	round_count = 0
	
	#Iterates through round key schedule in reverse order
	for round_key in reversed(round_keys):
		temp = BitVector(size = 0)
		for i in range(0, len(encrypted_bv) // BLOCKSIZE):
		
			bitvec = previous_block[i*BLOCKSIZE:(i+1)*BLOCKSIZE]
			
			'''
			-> Inverse Shift Rows in state array (Occurs every round)
			-> Inverse Substitute Bytes (Occurs every round) 
			-> Add round key (Occurs every round in addition to before round 1)
			-> Inverse Mix Columns in state array (Occurs every round except last)
			'''
			if (round_count>0):
				bitvec = inv_shift_rows(bitvec)
				bitvec = inv_sub_bytes(bitvec)
			bitvec = add_round_key(bitvec, round_key)
			if (round_count>0 and round_count<NUM_ROUNDS):
				bitvec = inv_mix_cols(bitvec)
			temp+=bitvec
		
		#Saves current changed block for next round
		previous_block = temp
		round_count+=1

	#Removes excess padding from recovered text
	recovered = remove_padding(previous_block)
	
	return recovered.get_bitvector_in_ascii()

'''
Wrapper function that calls the encryption function and writes the result into a given file
'''

def aes_encryption(message_path, encrypted_path, key):
	ciphertext = encrypt(message_path, key)
	encrypted_file = open(encrypted_path, "w")
	encrypted_file.write(ciphertext)
	encrypted_file.close()
	return ciphertext

'''
Wrapper function that calls the decryption function and writes the result into a given file
'''
def aes_decryption(encrypted_path,decrypted_path, key):

	recovered = decrypt(encrypted_path, key)
	decrypted_file = open(decrypted_path, "w")
	decrypted_file.write(recovered)
	decrypted_file.close()

	return recovered

'''
Prints the inputs and outputs of the program along with the runtime statistics
'''
def print_everything(message, key, ciphertext, recovered, encrypt_time, decrypt_time, program_runtime):
	print("Original")
	print(message)
	print("") 
	
	print("Key")
	print(key)
	print("")
	
	print("Ciphertext")
	print(ciphertext)
	print("")
	
	print("Recovered Text")
	print(recovered)
	print("")
	 
	print("Encrypt runtime = {} seconds".format(encrypt_time))
	print("Decrypt runtime = {} seconds".format(decrypt_time))
	print("Program runtime = {} seconds".format(program_runtime))



	return


def main():


	if (len(sys.argv) != 4):
		print("You need to have 3 argument files in this order: message, encrypted, decrypted")
		sys.exit()

	start_time = time.time()

	message_path = sys.argv[1]
	encrypted_path = sys.argv[2]
	decrypted_path = sys.argv[3]


	message_file = open(message_path, "r")
	message = message_file.read()
	message_file.close()

	#Assume a 128-bit key is given
	key = "hackingteamitaly"

	#Encrypts plaintext and writes ciphertext into file and records encryption time (pads original message if necessary)
	encrypt_start = time.time()
	ciphertext = aes_encryption(message_path, encrypted_path, key)
	encrypt_end = time.time()
	encrypt_time = (encrypt_end - encrypt_start)


	#Decrypts ciphertext and writes plaintext into file and records decryption time (any padding is removed)
	decrypt_start = time.time()
	recovered = aes_decryption(encrypted_path,decrypted_path, key)
	decrypt_end = time.time()
	decrypt_time = (decrypt_end-decrypt_start)


	
	#Prints out plaintext, key, ciphertext, recovered text, and runtimes to standard output
	print_everything(message, key, ciphertext, recovered, encrypt_time, decrypt_time, time.time()-start_time)	
	return


if __name__ == "__main__":
	main()
