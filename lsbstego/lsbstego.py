from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
from base64 import b64encode
from hashlib import sha256
from PIL import Image
from sys import argv

def to_bin(data: bytes) -> str:
	return ''.join(f'{byte:08b}' for byte in data)

def from_bin(binary_str: str) -> bytes:
	bytes_list = [binary_str[i:i+8] for i in range(0, len(binary_str), 8)]
	return bytes(int(b, 2) for b in bytes_list if len(b) == 8)

def int_to_nbits(n: int, bits: int) -> str:
	return f'{n:0{bits}b}'

def bits_to_int(bstr: str) -> int:
	return int(bstr, 2)

def derive_positions(length: int, max_pos: int, seed: bytes) -> list[int]:
	pos_set = set()
	pos_list = []
	counter = 0
	while len(pos_list) < length:
		h = sha256(seed + counter.to_bytes(4, 'big')).digest()
		for i in range(0, len(h), 4):
			if len(pos_list) >= length:
				break
			val = int.from_bytes(h[i:i+4], 'big') % max_pos
			if val not in pos_set:
				pos_set.add(val)
				pos_list.append(val)
		counter += 1
	return pos_list

def encrypt_message(message: str, key: bytes, iv: bytes) -> bytes:
	cipher = AES.new(key, AES.MODE_CBC, iv)
	padded = pad(message.encode(), AES.block_size)
	encrypted = cipher.encrypt(padded)
	return encrypted

def decrypt_message(ciphertext: bytes, key: bytes, iv: bytes) -> str:
	cipher = AES.new(key, AES.MODE_CBC, iv)
	decrypted = cipher.decrypt(ciphertext)
	unpadded = unpad(decrypted, AES.block_size)
	return unpadded.decode(errors='ignore')

def hide_data(img_path, message, key_str, iv_str, start_marker_bin, end_marker_bin, output_path):
	if len(key_str) != 32 or len(iv_str) != 16:
		print('error: key must be 32 chars and iv 16 chars')
		return
	key = key_str.encode()
	iv = iv_str.encode()
	encrypted = encrypt_message(message, key, iv)
	print('debug encrypted message (base64):', b64encode(encrypted).decode())
	start_len_bin = int_to_nbits(len(start_marker_bin), 16)
	end_len_bin = int_to_nbits(len(end_marker_bin), 16)
	data_bin = start_len_bin + start_marker_bin + to_bin(encrypted) + end_len_bin + end_marker_bin
	data_len = len(data_bin)
	img = Image.open(img_path)
	if img.mode != 'RGB':
		img = img.convert('RGB')
	width, height = img.size
	pixels = img.load()
	max_bits = width * height * 3
	if data_len > max_bits:
		print('error: message too long for this image')
		return
	positions = derive_positions(data_len, max_bits, key + iv)
	for i, bit_pos in enumerate(positions):
		pixel_index = bit_pos // 3
		color_channel = bit_pos % 3
		x = pixel_index % width
		y = pixel_index // width
		r, g, b = pixels[x, y]
		bit = int(data_bin[i])
		if color_channel == 0:
			r = (r & ~1) | bit
		elif color_channel == 1:
			g = (g & ~1) | bit
		else:
			b = (b & ~1) | bit
		pixels[x, y] = (r, g, b)
	img.save(output_path)
	print(f'message hidden in \'{output_path}\'')

def extract_data(img_path, key_str, iv_str, start_marker_bin, end_marker_bin):
	if len(key_str) != 32 or len(iv_str) != 16:
		print('error: key must be 32 chars and iv 16 chars')
		return
	key = key_str.encode()
	iv = iv_str.encode()
	img = Image.open(img_path)
	if img.mode != 'RGB':
		img = img.convert('RGB')
	width, height = img.size
	pixels = img.load()
	max_bits = width * height * 3
	positions = derive_positions(max_bits, max_bits, key + iv)
	bits_collected = []
	for bit_pos in positions:
		pixel_index = bit_pos // 3
		color_channel = bit_pos % 3
		x = pixel_index % width
		y = pixel_index // width
		r, g, b = pixels[x, y]
		if color_channel == 0:
			bits_collected.append(str(r & 1))
		elif color_channel == 1:
			bits_collected.append(str(g & 1))
		else:
			bits_collected.append(str(b & 1))
	binary_str = ''.join(bits_collected)
	if len(binary_str) < 16:
		print('error: not enough data to read start marker length')
		return
	start_len = bits_to_int(binary_str[:16])
	print(f'debug start length (bits): {start_len}')
	if len(binary_str) < 16 + start_len:
		print('error: not enough data to read start marker')
		return
	start_mark_extracted = binary_str[16:16+start_len]
	print(f'debug start marker expected length: {len(start_marker_bin)}')
	print(f'debug start marker extracted: {start_mark_extracted}')
	if start_mark_extracted != start_marker_bin:
		print('error: start marker does not match')
		return
	candidates = []
	start_search_pos = 16 + start_len
	end_marker_len = len(end_marker_bin)
	pos = binary_str.find(end_marker_bin, start_search_pos)
	while pos != -1:
		if pos < 16:
			pos = binary_str.find(end_marker_bin, pos + 1)
			continue
		end_len_bin_candidate = binary_str[pos - 16:pos]
		end_len_candidate = bits_to_int(end_len_bin_candidate)
		print(f'debug end_len_bin: {end_len_bin_candidate} ({end_len_candidate} bits)')
		print(f'debug expected end_marker length: {end_marker_len} bits')
		if end_len_candidate == end_marker_len:
			candidates.append((pos - 16, pos, end_len_candidate))
		pos = binary_str.find(end_marker_bin, pos + 1)
	if not candidates:
		print('error: no valid end marker found')
		return
	for (end_len_start_pos, end_marker_start_pos, end_len_val) in candidates:
		message_start = 16 + start_len
		message_end = end_len_start_pos
		if message_end <= message_start:
			continue
		hidden_bin = binary_str[message_start:message_end]
		hidden_bytes = from_bin(hidden_bin)
		print(f'debug testing candidate: end_len pos {end_len_start_pos}, end_marker pos {end_marker_start_pos}')
		try:
			decrypted = decrypt_message(hidden_bytes, key, iv)
			print(f'message extracted: {decrypted}')
			return
		except Exception as e:
			print(f'error: failed to decrypt with candidate at pos {end_len_start_pos}: {str(e)}')
	print('error: could not extract a valid message with any end marker found')

def main():
	if len(argv) < 2:
		print('usage:')
		print('hide: python script.py hide <input_image> <message> <key32> <iv16> <start_marker_bin> <end_marker_bin> <output_image>')
		print('extract: python script.py extract <image_with_message> <key32> <iv16> <start_marker_bin> <end_marker_bin>')
		return
	action = argv[1]
	if action == 'hide':
		if len(argv) != 9:
			print('usage hide: python script.py hide <input_image> <message> <key32> <iv16> <start_marker_bin> <end_marker_bin> <output_image>')
			return
		_, _, img_in, msg, key, iv, start_mark, end_mark, out_img = argv
		hide_data(img_in, msg, key, iv, start_mark, end_mark, out_img)
	elif action == 'extract':
		if len(argv) != 7:
			print('usage extract: python script.py extract <image_with_message> <key32> <iv16> <start_marker_bin> <end_marker_bin>')
			return
		_, _, img_in, key, iv, start_mark, end_mark = argv
		extract_data(img_in, key, iv, start_mark, end_mark)
	else:
		print('error: unrecognized action. use "hide" or "extract"')

if __name__ == '__main__':main()
	# by azuk4r
	# ¬_¬
