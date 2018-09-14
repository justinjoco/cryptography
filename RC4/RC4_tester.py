#!/usr/bin/env python2.7


from Joco_RC4_class import *
import filecmp
rc4Cipher = RC4('abc1ef4hijklxnop')

originalImageFile = open("winterTown.ppm", "r")
headerList = []
for i in range(3):
	headerList.append(originalImageFile.readline())

originalImage = open("winterTownNoHeader.ppm", "r")
encryptedImage = rc4Cipher.encrypt(originalImage)


'''
encrypted_file = open("encrypted.ppm", "w")
for elem in headerList:
	encrypted_file.write(elem)
encrypted_file.write(encryptedImage)
encrypted_file.close()
'''

encrypted_image = open("encrypted.ppm", "r")

decryptedImage = rc4Cipher.decrypt(encrypted_image)
'''
decrypted_file = open("decrypted.ppm", "w")
for elem in headerList:
	decrypted_file.write(elem)
decrypted_file.write(decryptedImage)
decrypted_file.close()
'''
if filecmp.cmp("winterTownNoHeader.ppm","decrypted.ppm"):
	print("Success")
else:
	print("Failure")
