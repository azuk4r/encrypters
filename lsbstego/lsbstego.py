from Crypto.Util.Padding import pad,unpad
from Crypto.Cipher import AES
from base64 import b64encode
from hashlib import sha256
from PIL import Image
from sys import argv

RGB_PERMUTATIONS=[(0,1,2),(0,2,1),(1,0,2),(1,2,0),(2,0,1),(2,1,0)]

def to_bin(data:bytes)->str: return ''.join(f'{byte:08b}' for byte in data)
def from_bin(binary_str:str)->bytes: return bytes(int(binary_str[i:i+8], 2) for i in range(0,len(binary_str),8) if len(binary_str[i:i+8])==8)
def int_to_nbits(n:int,bits:int)->str: return f'{n:0{bits}b}'
def bits_to_int(bstr:str)->int: return int(bstr,2)

def derive_positions(length:int,max_pos:int,seed:bytes):
	pos_set=set()
	pos_list=[]
	counter=0
	while len(pos_list)<length:
		h=sha256(seed+counter.to_bytes(4,'big')).digest()
		for i in range(0,len(h),4):
			if len(pos_list)>=length:break
			val=int.from_bytes(h[i:i+4],'big')%max_pos
			if val not in pos_set:
				pos_set.add(val)
				perm_index=h[i]%len(RGB_PERMUTATIONS)
				pos_list.append((val,RGB_PERMUTATIONS[perm_index]))
		counter+=1
	return pos_list

def encrypt_message(message:str,key:bytes,iv:bytes)->bytes:
	cipher=AES.new(key,AES.MODE_CBC,iv)
	padded=pad(message.encode(),AES.block_size)
	return cipher.encrypt(padded)

def decrypt_message(ciphertext:bytes,key:bytes,iv:bytes)->str:
	cipher=AES.new(key,AES.MODE_CBC,iv)
	decrypted=cipher.decrypt(ciphertext)
	return unpad(decrypted,AES.block_size).decode(errors='ignore')

def hide_data(img_path,message,key_str,iv_str,start_marker_bin,end_marker_bin,output_path):
	if len(key_str)!=32 or len(iv_str)!=16:print('error: key must be 32 chars and iv 16 chars');return
	key=key_str.encode()
	iv=iv_str.encode()
	encrypted=encrypt_message(message,key,iv)
	#print('debug encrypted message (base64):',b64encode(encrypted).decode())
	start_len_bin=int_to_nbits(len(start_marker_bin),16)
	end_len_bin=int_to_nbits(len(end_marker_bin),16)
	data_bin=start_len_bin+start_marker_bin+to_bin(encrypted)+end_len_bin+end_marker_bin
	data_len=len(data_bin)
	img=Image.open(img_path)
	if img.mode!='RGB':img=img.convert('RGB')
	width,height=img.size
	pixels=img.load()
	max_bits=width*height*3
	if data_len>max_bits:print('error: message too long for this image');return
	positions=derive_positions(data_len,max_bits,key+iv)
	for i,(bit_pos,channel_order) in enumerate(positions):	# apply lsb
		pixel_index=bit_pos//3
		color_channel=bit_pos%3  # select a rgb channel
		x=pixel_index%width
		y=pixel_index//width
		r,g,b=pixels[x,y]
		channels=[r,g,b]
		permuted=[channels[channel_order[0]],channels[channel_order[1]],channels[channel_order[2]]]  # but the channel is unknown
		old_bit=permuted[color_channel]&1
		new_bit=int(data_bin[i])
		permuted[color_channel]=(permuted[color_channel]&~1)|new_bit
		final_channels=[0,0,0]  # undo permutation
		for idx,val in enumerate(channel_order):final_channels[val]=permuted[idx]
		pixels[x,y]=tuple(final_channels)
		#print(f'hide - pixel ({x},{y}): original={{r:{r}, g:{g}, b:{b}}}, permuted={{r:{permuted[0]}, g:{permuted[1]}, b:{permuted[2]}}}, channel_order={channel_order}, color_channel={color_channel}, old_bit={old_bit}, new_bit={new_bit}')  # print to debug
	img.save(output_path)
	print(f'message hidden in "{output_path}"')

def extract_data(img_path,key_str,iv_str,start_marker_bin,end_marker_bin):
	if len(key_str)!=32 or len(iv_str)!=16:print('error: key must be 32 chars and iv 16 chars');return
	key=key_str.encode()
	iv=iv_str.encode()
	img=Image.open(img_path)
	if img.mode!='RGB':img=img.convert('RGB')
	width,height=img.size
	pixels=img.load()
	max_bits=width*height*3
	positions=derive_positions(max_bits,max_bits,key+iv)
	bits_collected=[]
	for bit_pos,channel_order in positions:	# extract lsb
		pixel_index=bit_pos//3
		color_channel=bit_pos%3
		x=pixel_index%width
		y=pixel_index//width
		r,g,b=pixels[x,y]
		channels=[r,g,b]
		permuted=[channels[channel_order[0]],channels[channel_order[1]],channels[channel_order[2]]]
		bit=permuted[color_channel]&1
		bits_collected.append(str(bit))
		#print(f'extract - pixel ({x},{y}): original={{r:{r}, g:{g}, b:{b}}}, permuted={{r:{permuted[0]}, g:{permuted[1]}, b:{permuted[2]}}}, channel_order={channel_order}, color_channel={color_channel}, bit={bit}')
	binary_str=''.join(bits_collected)
	if len(binary_str)<16:print('error: not enough data to read start marker length');return
	start_len=bits_to_int(binary_str[:16])
	if len(binary_str)<16+start_len:print('error: not enough data to read start marker');return
	start_mark_extracted=binary_str[16:16+start_len]
	if start_mark_extracted!=start_marker_bin:print('error: start marker does not match or incorrect key/iv');return
	candidates=[]	# for end markers
	start_search_pos=16+start_len
	end_marker_len=len(end_marker_bin)
	pos=binary_str.find(end_marker_bin,start_search_pos)
	while pos!=-1:
		if pos<16:pos=binary_str.find(end_marker_bin,pos+1);continue
		end_len_bin_candidate=binary_str[pos-16:pos]
		end_len_candidate=bits_to_int(end_len_bin_candidate)
		if end_len_candidate==end_marker_len:candidates.append((pos-16,pos,end_len_candidate))
		pos=binary_str.find(end_marker_bin,pos+1)
	if not candidates:print('error: no valid end marker found');return
	for (end_len_start_pos,end_marker_start_pos,end_len_val) in candidates:	# search for content within the markers
		message_start=16+start_len
		message_end=end_len_start_pos
		if message_end<=message_start:continue
		hidden_bin=binary_str[message_start:message_end]
		hidden_bytes=from_bin(hidden_bin)
		try:
			decrypted=decrypt_message(hidden_bytes,key,iv)
			print(f'message extracted: {decrypted}')
			return
		except Exception:continue
	print('error: could not extract a valid message with any end marker found')

def main():
	if len(argv)<2:print('usage:');print('hide: python lsbstego.py hide <input_image> <message> <key32> <iv16> <start_marker_bin> <end_marker_bin> <output_image>');print('extract: python lsbstego.py extract <image_with_message> <key32> <iv16> <start_marker_bin> <end_marker_bin>');return
	action=argv[1]
	if action=='hide':
		if len(argv)!=9:print('usage hide: python lsbstego.py hide <input_image> <message> <key32> <iv16> <start_marker_bin> <end_marker_bin> <output_image>');return
		_,_,img_in,msg,key,iv,start_mark,end_mark,out_img=argv
		hide_data(img_in,msg,key,iv,start_mark,end_mark,out_img)
	elif action=='extract':
		if len(argv)!=7:print('usage extract: python lsbstego.py extract <image_with_message> <key32> <iv16> <start_marker_bin> <end_marker_bin>');return
		_,_,img_in,key,iv,start_mark,end_mark=argv
		extract_data(img_in,key,iv,start_mark,end_mark)
	else:print('error: unrecognized action. use "hide" or "extract"')

if __name__ == '__main__':main()
	# by azuk4r
	# ¬_¬
