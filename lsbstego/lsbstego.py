from os.path import exists,basename,splitext
from Crypto.Util.Padding import pad,unpad
from base64 import b64encode,b64decode
from lzma import compress,decompress
from argparse import ArgumentParser
from Crypto.Cipher import AES
from hashlib import sha256
from PIL import Image
from math import gcd

RGB_PERMUTATIONS=[(0,1,2),(0,2,1),(1,0,2),(1,2,0),(2,0,1),(2,1,0)]
COMPRESSED_EXTS={'.gz','.zip','.bz2','.7z','.xz','.jpg','.jpeg','.png','.gif','.mp3','.mp4','.pdf'}
BAD_OUTPUT_EXTS={'.jpg','.jpeg','.webp'}
Image.MAX_IMAGE_PIXELS=None     # remove pillow warning

def to_bin(data:bytes)->str: return ''.join(f'{byte:08b}' for byte in data)
def from_bin(binary_str:str)->bytes: return bytes(int(binary_str[i:i+8],2) for i in range(0,len(binary_str),8) if len(binary_str[i:i+8])==8)
def int_to_nbits(n:int,bits:int)->str: return f'{n:0{bits}b}'
def bits_to_int(bstr:str)->int: return int(bstr,2)

def derive_positions(length:int,max_pos:int,seed:bytes):
	total_pixels=max_pos//3
	seed_hash=sha256(seed).digest()
	a=int.from_bytes(seed_hash[:8],'big')|1
	a%=total_pixels
	if a==0:a=1	# ensure coprime
	while gcd(a,total_pixels)!=1:
		a=(a+2)%total_pixels
		if a==0:a=1
	b=int.from_bytes(seed_hash[8:16],'big')%total_pixels
	count=0
	for i in range(total_pixels):
		p=(a*i+b)%total_pixels
		pixel_hash=sha256(seed+p.to_bytes(8,'big')).digest()
		permutation_idx=pixel_hash[0]%len(RGB_PERMUTATIONS)	# choose rgb permutation
		channel_order=RGB_PERMUTATIONS[permutation_idx]
		for permuted_pos in range(3):	# choose rgb permuted channel
			if count>=length:return
			yield (p,channel_order,permuted_pos)
			count+=1
			if count>=length:return

def encrypt_text(text:str,key:bytes,iv:bytes)->bytes:
	cipher=AES.new(key,AES.MODE_CBC,iv)
	return cipher.encrypt(pad(text.encode(),AES.block_size))

def decrypt_text(ciphertext:bytes,key:bytes,iv:bytes)->str:
	cipher=AES.new(key,AES.MODE_CBC,iv)
	return unpad(cipher.decrypt(ciphertext),AES.block_size).decode(errors='ignore')

def set_pixel_bit(img,width,pixel_idx,channel_order,permuted_pos,bit):
	x,y=pixel_idx%width,pixel_idx//width
	r,g,b=img.getpixel((x,y))
	channels=[r,g,b]
	permuted=[channels[channel_order[0]],channels[channel_order[1]],channels[channel_order[2]]]
	permuted[permuted_pos]=(permuted[permuted_pos]&~1)|bit	# apply lsb
	restored=[0,0,0]
	for idx,val in enumerate(channel_order):restored[val]=permuted[idx] 	# undo permutation
	img.putpixel((x,y),tuple(restored))

def hide_data(img_path,key_str,iv_str,text,output_path):
	if len(key_str)!=32 or len(iv_str)!=16:print('error: key must be 32 chars and iv 16 chars');return
	if splitext(output_path)[1].lower() in BAD_OUTPUT_EXTS:print(f'error: format "{splitext(output_path)[1]}" is not supported, use png or another lossless format');return
	key,iv=key_str.encode(),iv_str.encode()
	encrypted=encrypt_text(text,key,iv)
	encrypted_bin=to_bin(encrypted)
	encrypted_bin_len=len(encrypted_bin)
	prefix=int_to_nbits(encrypted_bin_len,32)
	data=prefix+encrypted_bin
	img=Image.open(img_path).convert('RGB')
	width,height=img.size
	max_bits=width*height*3
	if len(data)>max_bits:print('error: data length exceeds image capacity');return
	for i,(pixel_idx,channel_order,permuted_pos) in enumerate(derive_positions(len(data),max_bits,key+iv)):set_pixel_bit(img,width,pixel_idx,channel_order,permuted_pos,int(data[i]))
	img.save(output_path)
	print(f'data hidden in "{output_path}"')

def get_pixel_bit(img,width,pixel_idx,channel_order,permuted_pos):
	x,y=pixel_idx%width,pixel_idx//width
	r,g,b=img.getpixel((x,y))
	channels=[r,g,b]
	permuted=[channels[channel_order[0]],channels[channel_order[1]],channels[channel_order[2]]]
	return permuted[permuted_pos]&1 	# extract lsb

def extract_data(img_path,key_str,iv_str,output_file=None):
	if len(key_str)!=32 or len(iv_str)!=16:print('error: key must be 32 chars and iv 16 chars');return
	key,iv=key_str.encode(),iv_str.encode()
	img=Image.open(img_path).convert('RGB')
	width,height=img.size
	max_bits=width*height*3
	bits=[]
	for pos in derive_positions(32,max_bits,key+iv):bits.append(str(get_pixel_bit(img,width,*pos)))
	data_len=bits_to_int(''.join(bits))
	bits=[]
	positions_gen=derive_positions(32+data_len,max_bits,key+iv)
	for _ in range(32):next(positions_gen)
	for pos in positions_gen:bits.append(str(get_pixel_bit(img,width,*pos)))
	hidden_bytes=from_bin(''.join(bits))
	try:
		decrypted=decrypt_text(hidden_bytes,key,iv)
		if output_file:
			if '|' in decrypted:
				filename,b64_data=decrypted.split('|',1)
				file_data=b64decode(b64_data)
				file_ext=splitext(filename)[1].lower()
				if file_ext in COMPRESSED_EXTS:data=file_data
				else:data=decompress(file_data)
				with open(filename,'wb') as f:f.write(data)
				print(f'file extracted as "{filename}"')
			else:print(f'error: extracted data is not a file')
		else:print(f'text: {decrypted}')
	except Exception as e:print(f'error: could not decrypt - {e}')

def main():
	parser=ArgumentParser(description='hide aes256-cbc encrypted data in images using lsb stego')
	subparsers=parser.add_subparsers(dest='command',required=True)
	sparser=ArgumentParser(add_help=False)	# shared parser
	sparser.add_argument('image',help='path to image file')
	sparser.add_argument('key',help='aes key (32 characters)')
	sparser.add_argument('iv',help='initialization vector (16 characters)')
	hparser=subparsers.add_parser('hide',parents=[sparser],help='hide data')
	hgroup=hparser.add_mutually_exclusive_group(required=True)
	hgroup.add_argument('--text',help='text to hide')
	hgroup.add_argument('--file',help='file to hide')
	hparser.add_argument('output',nargs='?',default='output.png',help='output image')
	eparser=subparsers.add_parser('extract',parents=[sparser],help='extract data')
	egroup=eparser.add_mutually_exclusive_group()
	egroup.add_argument('--text',action='store_true',help='extract as text (default)')
	egroup.add_argument('--file',action='store_true',help='extract as file')
	args=parser.parse_args()
	if args.command=='hide':
		if args.file:
			if not exists(args.file):
				print(f'error: file "{args.file}" not found')
				return
			with open(args.file,'rb') as f:file_data=f.read()
			filename=basename(args.file)
			file_ext=splitext(args.file)[1].lower()
			if file_ext in COMPRESSED_EXTS:b64_data=b64encode(file_data).decode('ascii')
			else:
				compressed=compress(file_data)
				b64_data=b64encode(compressed).decode('ascii')
			text=f'{filename}|{b64_data}'
		else:text=args.text
		hide_data(args.image,args.key,args.iv,text,args.output)
	else:
		output_file=args.file
		extract_data(args.image,args.key,args.iv,output_file)

if __name__=='__main__':main()
	# by azuk4r
	# ¬_¬
