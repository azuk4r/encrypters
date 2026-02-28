from os.path import exists,basename,splitext
from lzma import compress,decompress
from argparse import ArgumentParser
from sys import exit,stdin

UNICODES=['\u2060','\u200D','\u200B','\u200C','\u200E','\u200F','\uFEFF','\u2061','\u2062','\u2063','\u2064','\u2066','\u2067','\u2068','\u2069','\u034F']
COMPRESSED_EXTS={'.gz','.zip','.bz2','.7z','.xz','.jpg','.jpeg','.png','.gif','.mp3','.mp4','.pdf'}

def encode(data,bin,char_set=None):
	if char_set is None:char_set=UNICODES
	if bin:return ''.join(UNICODES[(byte>>shift)&1] for byte in data for shift in range(7,-1,-1))
	else:return ''.join(char_set[(byte>>4)&0xF]+char_set[byte&0xF] for byte in data)

def decode(s,bin,char_set=None):
	if char_set is None:char_set=UNICODES
	if bin:
		m={c:i for i,c in enumerate(UNICODES[:2])}
		chars=[c for c in s if c in m]
		if len(chars)%8:raise ValueError('not multiple of 8')
		out=bytearray()
		for i in range(0,len(chars),8):
			v=0
			for j in range(8):v=(v<<1)|m[chars[i+j]]
			out.append(v)
		return bytes(out)
	else:
		m={c:i for i,c in enumerate(char_set)}
		chars=[c for c in s if c in m]
		if len(chars)%2:raise ValueError('odd count')
		out=bytearray()
		for i in range(0,len(chars),2):out.append((m[chars[i]]<<4)|m[chars[i+1]])
		return bytes(out)

def permute_unicodes(seed_bytes):
	import random,hashlib
	seed=int.from_bytes(hashlib.sha256(seed_bytes).digest(),'big')
	rng=random.Random(seed)
	shuffled=UNICODES[:]
	for i in range(len(shuffled)-1,0,-1):
		j=rng.randint(0,i)
		shuffled[i],shuffled[j]=shuffled[j],shuffled[i]
	return shuffled

def main():
	p=ArgumentParser(description='Zero‑width steganography with optional AES encryption and file support')
	sp=p.add_subparsers(dest='command',required=True)
	ep=sp.add_parser('encode',help='encode data to invisible characters')
	ep.add_argument('-t','--text',metavar='TEXT',help='text to encode')
	ep.add_argument('-f','--file',metavar='PATH',help='file to encode')
	ep.add_argument('-k','--key',metavar='KEY',help='AES key (32 bytes)')
	ep.add_argument('-i','--iv',metavar='IV',help='AES IV (16 bytes)')
	ep.add_argument('-b','--bin',action='store_true',help='use 2‑char mode')
	ep.add_argument('-o','--output',metavar='FILE',help='output file')
	dp=sp.add_parser('decode',help='decode invisible characters back to data')
	dp.add_argument('input',metavar='FILE',help='file containing invisible characters')
	dp.add_argument('-k','--key',metavar='KEY',help='AES key (32 bytes)')
	dp.add_argument('-i','--iv',metavar='IV',help='AES IV (16 bytes)')
	dp.add_argument('-b','--bin',action='store_true',help='use 2‑char mode')
	dp.add_argument('--file',action='store_true',help='extract as file (requires embedded name)')
	dp.add_argument('-o','--output',metavar='FILE',help='output file (for text) or override filename for file extraction')
	args=p.parse_args()
	if args.command=='decode':
		with open(args.input,'r',encoding='utf-8') as f:s=f.read()
		try:
			char_set=None
			if args.key and args.iv and not args.bin:
				seed=(args.key+args.iv).encode()
				char_set=permute_unicodes(seed)
			data=decode(s,args.bin,char_set)
			if args.key and args.iv:
				if len(args.key)!=32 or len(args.iv)!=16:exit('key must be 32 bytes, iv 16 bytes')
				try:
					from Crypto.Cipher import AES
					from Crypto.Util.Padding import unpad
				except ImportError:exit('Crypto module not installed. Install pycryptodome')
				cipher=AES.new(args.key.encode(),AES.MODE_CBC,args.iv.encode())
				data=unpad(cipher.decrypt(data),AES.block_size)
			if args.file:
				if b'\x00' not in data:exit('error: no file data found (missing null separator)')
				name,content=data.split(b'\x00',1)
				fname=name.decode('utf-8')
				ext=splitext(fname)[1].lower()
				if ext not in COMPRESSED_EXTS:
					try:content=decompress(content)
					except:pass
				out_path=args.output if args.output else fname
				with open(out_path,'wb') as f:f.write(content)
				print(f'file extracted: {out_path}')
			else:
				text=data.decode('utf-8','replace')
				if args.output:
					with open(args.output,'w',encoding='utf-8') as f:f.write(text)
					print('text saved')
				else:print(text,end='')
		except Exception as e:exit(f'error: {e}')	
	else:	# encode
		if args.text and args.file:exit('use --text or --file, not both')
		if not args.text and not args.file:
			t=stdin.read()
			if not t:exit(1)
			data=t.encode('utf-8')
		elif args.text:data=args.text.encode('utf-8')
		else:	# file
			if not exists(args.file):exit('file not found')
			with open(args.file,'rb') as f:file_data=f.read()
			fname=basename(args.file)
			ext=splitext(args.file)[1].lower()
			if ext in COMPRESSED_EXTS:compressed=file_data
			else:compressed=compress(file_data)
			data=fname.encode('utf-8')+b'\x00'+compressed
		if args.key and args.iv:
			if len(args.key)!=32 or len(args.iv)!=16:exit('key must be 32 bytes, iv 16 bytes')
			try:
				from Crypto.Cipher import AES
				from Crypto.Util.Padding import pad
			except ImportError:exit('Crypto module not installed. Install pycryptodome')
			cipher=AES.new(args.key.encode(),AES.MODE_CBC,args.iv.encode())
			data=cipher.encrypt(pad(data,AES.block_size))
		char_set=None
		if args.key and args.iv and not args.bin:
			seed=(args.key+args.iv).encode()
			char_set=permute_unicodes(seed)
		r=encode(data,args.bin,char_set)
		if args.output:
			with open(args.output,'w',encoding='utf-8') as f:f.write(r)
			print('encoded saved')
		else:print(r,end='')

if __name__=='__main__':main()
	# by azuk4r
	# ¬_¬
