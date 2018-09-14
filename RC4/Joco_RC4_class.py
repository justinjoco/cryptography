#!usr/bin/env python2.7

#Class that implements Ron's Code 4 algorithm
class RC4:

	#Intializes S and T vectors and pseudorandom byte stream 
	s_vector = [x for x in range(256)]
	t_vector = [None for x in range(256)]
	random_byte_stream = []
	
	#Save key and create S and T for RC4 object
	def __init__(self, key):
		self.key = key
		self.create_t_vector()
		self.initialize_s_vector()

	#Encrypts image data using RC4: XORing plaintext with pseudorandom byte stream
	def encrypt(self, image):
		self.set_image(image.read())
		self.create_byte_stream()
		self.image = [ord(a) for a in self.image]
		
		ret_str = ""
		for i in range(0, len(self.image)):
			ret_byte = self.random_byte_stream[i] ^ self.image[i]
			ret_str += chr(ret_byte)
		
		out_file = open("encrypted.ppm", "w")
		out_file.write(ret_str)
		out_file.close()
		
		return out_file

	#Decrypted image data by XORing encrypted image with RC4 random byte stream
	def decrypt(self, encrypted_image):
		ret_str = ""
		self.encrypted_image =  encrypted_image.read()
		self.encrypted_image = [ord(a) for a in self.encrypted_image]
		
		for i in range(0, len(self.encrypted_image)):
			ret_byte = self.encrypted_image[i] ^ self.random_byte_stream[i]
			ret_str += chr(ret_byte)

		out_file = open("decrypted.ppm", "w")
		out_file.write(ret_str)
		out_file.close()
		return out_file

	#Utility function to print out S for testing and debugging
	def print_s_vector(self):
		for element in self.s_vector:
			print(element)
		return

	#Setter for image
	def set_image(self, image):
		self.image = image
		return

	#Prints out image bytes for debugging purposes
	def print_image_bytes(self):
		for elem in self.image:
			print (elem)
		return

	#Prints out T for debugging 
	def print_t_vector(self):
		for element in self.t_vector:
			print(element)
		return

	
	#Creates T vector based on encryption key
	def create_t_vector(self):
		key_length = len(self.key)
		for i in range(256):
			self.t_vector[i] = self.key[i%key_length]
		self.t_vector = [ord(element) for element in self.t_vector]
		return



	#First permutation of S using initial S and T
	def initialize_s_vector(self):
		j = 0
		for i in range(256):
			j = (j + self.s_vector[i] + self.t_vector[i])% 256
			temp = self.s_vector[i]
			self.s_vector[i] = self.s_vector[j]
			self.s_vector[j] = temp

		return

	#Creates a pseudorandom byte stream with the same length as the image data
	def create_byte_stream(self):
		i= 0
		j = 0
		for n in range(0, len(self.image)):
			i = (i + 1)% 256
			j = (j + self.s_vector[i])% 256
			temp = self.s_vector[i]
			self.s_vector[i] = self.s_vector[j]
			self.s_vector[j] = temp
			k = (self.s_vector[i] + self.s_vector[j])%256
			self.random_byte_stream.append(self.s_vector[k])
		return
