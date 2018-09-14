#! usr/bin/env python2.7

import sys
import time
from BitVector import *

BLOCKSIZE = 64

NUM_ROUNDS = 16

key_permutation_1 = [56,48,40,32,24,16,8,0,57,49,41,33,25,17,
	9,1,58,50,42,34,26,18,10,2,59,51,43,35,
	62,54,46,38,30,22,14,6,61,53,45,37,29,21,
	13,5,60,52,44,36,28,20,12,4,27,19,11,3]


key_permutation_2 = [13,16,10,23,0,4,2,27,14,5,20,9,22,18,11,
 3,25,7,15,6,26,19,12,1,40,51,30,36,46,
 54,29,39,50,44,32,47,43,48,38,55,33,52,
 45,41,49,35,28,31]

pboxPermutation = [15, 6, 19, 20, 28, 11, 27, 16,
0, 14, 22, 25, 4, 17, 30, 9,
1, 7, 23, 13, 31, 26, 2, 8,
18, 12, 29, 5, 21, 10, 3, 24]


expansion_permutation = [31, 0, 1, 2, 3, 4, 3, 4, 5, 6, 7, 8, 7, 8, 9,
10, 11, 12, 11, 12, 13, 14, 15, 16, 15, 16, 
17, 18, 19, 20, 19, 20, 21, 22, 23, 24, 23, 24, 25, 26, 27, 28, 27, 28, 29, 30, 31, 0]

shifts_for_round_key_gen = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]

s_boxes = {i:None for i in range(8)}

s_boxes[0] = [ [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
               [0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
               [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],
               [15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13] ]

s_boxes[1] = [ [15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],
               [3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],
               [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],
               [13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9] ]

s_boxes[2] = [ [10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],
               [13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],
               [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],
               [1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12] ]

s_boxes[3] = [ [7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],
               [13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],
               [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],
               [3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14] ]

s_boxes[4] = [ [2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],
               [14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],
               [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],
               [11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3] ]  

s_boxes[5] = [ [12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],
               [10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],
               [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],
               [4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13] ]

s_boxes[6] = [ [4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],
               [13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],
               [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],
               [6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12] ]

s_boxes[7] = [ [13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],
               [1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],
               [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],
               [2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11] ]




def getEncryptionKey(key):

	key = BitVector(textstring = key)
	key = key.permute(key_permutation_1)

	return key

def generateRoundKeys(encryptionKey):
	roundKeys = []
	key = encryptionKey.deep_copy()
	for count in range (0, NUM_ROUNDS):
		[LKey, RKey] = key.divide_into_two()
		shift = shifts_for_round_key_gen[count]
		LKey << shift
		RKey << shift
		key = LKey + RKey
		roundKey = key.permute(key_permutation_2)
		roundKeys.append(roundKey)

	return roundKeys

	
def substitute( expanded_half_block ):
    '''
    This method implements the step "Substitution with 8 S-boxes" step you see inside
    Feistel Function dotted box in Figure 4 of Lecture 3 notes.
    '''
    output = BitVector (size = 32)
    segments = [expanded_half_block[x*6:x*6+6] for x in range(8)]
    for sindex in range(len(segments)):
        row = 2*segments[sindex][0] + segments[sindex][-1]
        column = int(segments[sindex][1:-1])
        output[sindex*4:sindex*4+4] = BitVector(intVal = s_boxes[sindex][row][column], size = 4)
    return output        


def encrypt(messagePath, encryptionKey):
	messageFile = open(messagePath)
	
	message_bv = BitVector(textstring = messageFile.read()) 
   	roundKeys = generateRoundKeys(encryptionKey)

	#Set a previous block
	previous_block = message_bv

	#Initialize final encrypted bv
	msg_encrypted_bv = BitVector(size = 0)
	
	#Iterate through all round keys
	for roundKey in roundKeys:	
		
		#Make temporary ciphertext
  		temp = BitVector(size = 0)

		#Iterate through blocks of 64 bits
		for i in range(0, len(message_bv) // BLOCKSIZE):
			bitvec = previous_block[i*BLOCKSIZE: (i+1)*BLOCKSIZE]
			
			#Pass block through Feistel function 
			if len(bitvec) > 0:
				[LE, RE] = bitvec.divide_into_two()
				newRE = RE.permute( expansion_permutation )
				out_xor = newRE ^ roundKey 
				sboxOutput = substitute(out_xor)
				RE_modified = sboxOutput.permute(pboxPermutation)
				final_string = RE + (RE_modified ^ LE)
				temp+=final_string

		#Save ciphertext from current run
		previous_block = temp
		
	#Return final ciphertext bv into a hexstring
	msg_encrypted_bv = previous_block
	outputhex = msg_encrypted_bv.get_bitvector_in_hex()
	return outputhex

def decrypt(encryptedPath, key):

	encryptedFile = open(encryptedPath)
	encrypted_bv = BitVector(hexstring = encryptedFile.read())
	#Generate round keys
	roundKeys = generateRoundKeys(key)
	
	
	#Initialize recover text
	msg_decrypted_bv = BitVector(size = 0)
	
	#Set a previous block
	previous_block = encrypted_bv
	
	#Iterate through round keys in reverse
	for roundKey in reversed(roundKeys):
		
		#Set a temporary recover text bv
		temp = BitVector(size = 0)

		#Iterate through ciphertext in blocks of 64 bits
		for i in range(0, len(encrypted_bv) // BLOCKSIZE):
			bitvec = previous_block[i*BLOCKSIZE: (i+1)*BLOCKSIZE]
			
			#Pass ciphertext into Feistel structure
			if len(bitvec)>0:
				[RD, LD] = bitvec.divide_into_two()
				newRD = RD.permute(expansion_permutation)
				out_xor = newRD ^ roundKey
				sboxOutput = substitute(out_xor)
				RD_modified = sboxOutput.permute(pboxPermutation)
				final_string =  (RD_modified ^ LD) + RD
				temp += final_string

		#Save current recovered text
		previous_block = temp

	#Outputs final recovered text 
	msg_decrypted_bv = previous_block
	recoveredString = msg_decrypted_bv.get_bitvector_in_ascii()
	return recoveredString




def main():

	#Enforces parameters
	if (len(sys.argv))!= 5:
		print("You are required to have 4 argument files in this order: message, key, encrypted, decrypted")
		sys.exit()
   
	startTime = time.time()
	#Input paths
	messagePath = sys.argv[1]
	keyPath = sys.argv[2]

	#Output paths
	encryptedPath = sys.argv[3]
	decryptedPath = sys.argv[4]

	#Read the plaintext
	messageFile = open(messagePath, "r")
	message = messageFile.read() 
	messageFile.close()

	#Get encryption key from ascii key file
	keyFile = open(keyPath, "r")
	key = keyFile.read()
	keyText = key
	keyFile.close()
	key = getEncryptionKey(key)
	
	#Encrypts plaintext into a file as ciphertext
	cipherText = encrypt(messagePath, key)
	encryptedFile = open(encryptedPath, "w")
	encryptedFile.write(cipherText)
	encryptedFile.close()

	#Saves recovered text from a ciphertext file into a new file
	recoverText = decrypt(encryptedPath, key)	
	decryptedFile = open(decryptedPath, "w")
	decryptedFile.write(recoverText)
	decryptedFile.close()

	
	print("Original message")
	print(message)
	print("")

	print("Key")
	print(keyText)
	print("")

	print("Ciphertext")
	print(cipherText)
	print("")

	print("Recovered Text")
	print(recoverText)

	print("Program runtime = {} minutes".format((time.time()-startTime)/60))

if __name__ == "__main__":
	main()
