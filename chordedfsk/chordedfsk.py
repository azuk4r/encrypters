from numpy import linspace,zeros,zeros_like,sin,pi,concatenate,ones,pad,float32,int16,hanning
from os.path import basename,splitext,exists
from lzma import compress,decompress
from scipy.fft import rfft
from argparse import ArgumentParser
from soundfile import SoundFile
from Crypto.Cipher import AES
from hashlib import sha256

FREQ_MAP=[
	{'key':'0','note':'C','frequency':261.63},
	{'key':'1','note':'D','frequency':293.66},
	{'key':'2','note':'E','frequency':329.63},
	{'key':'3','note':'F','frequency':349.23},
	{'key':'4','note':'G','frequency':392.00},
	{'key':'5','note':'A','frequency':440.00},
	{'key':'6','note':'B','frequency':493.88},
	{'key':'7','note':'C','frequency':523.25},
	{'key':'8','note':'D','frequency':587.33},
	{'key':'9','note':'E','frequency':659.25},
	{'key':'a','note':'F','frequency':698.46},
	{'key':'b','note':'G','frequency':783.99},
	{'key':'c','note':'A','frequency':880.00},
	{'key':'d','note':'B','frequency':987.77},
	{'key':'e','note':'C','frequency':1046.50},
	{'key':'f','note':'D','frequency':1174.66}]
COMPRESSED_EXTS={'.gz','.zip','.bz2','.7z','.xz','.jpg','.jpeg','.png','.gif','.mp3','.mp4','.pdf'}

def _text(text): yield text.encode('utf-8')
def pad16(b): l=16-(len(b)%16);return b+bytes([l])*l
def unpad16(b): l=b[-1];return b[:-l] if 1<=l<=16 else b
def encrypt(b,key,iv): return AES.new(key,AES.MODE_CBC,iv).encrypt(pad16(b))
def decrypt(b,key,iv): return unpad16(AES.new(key,AES.MODE_CBC,iv).decrypt(b))
def _hex(it,key,iv): yield from (encrypt(data,key,iv).hex() for data in it)

def _file(path):
	data=open(path,'rb').read()
	ext=splitext(path)[1].lower()
	file_data=data if ext in COMPRESSED_EXTS else compress(data)
	name=basename(path).encode('utf-8')
	yield name+b'\x00'+file_data

def permute_freq_map(key:bytes,iv:bytes):
	seed=int.from_bytes(sha256(key+iv).digest(),'big')
	items=FREQ_MAP.copy()
	for i in reversed(range(1,len(items))):
		seed,j=divmod(seed,i+1)
		items[i],items[j]=items[j],items[i]
	kdict={item['key']:item for item in items}
	f2k={item['frequency']:item['key'] for item in items}
	return kdict,f2k,sorted(f2k.keys())

def gen_sound(freqs,dur=0.1):
	sr=44100
	n=int(sr*dur);t=linspace(0,dur,n,endpoint=False);w=zeros_like(t)
	for f,a in freqs:w+=a*sin(2*pi*f*t)
	a=int(sr*0.02);r=a;s=max(n-a-r,0)
	env=concatenate([linspace(0,1,a,endpoint=False),ones(s),linspace(1,0,r,endpoint=False)])
	if len(env)<len(w):env=pad(env,(0,len(w)-len(env)),'constant')
	w*=env;mx=max(abs(w)) if max(abs(w))>1e-9 else 1.0
	return (w/mx).astype(float32),sr

def gen_chords(h,key_dict):
	chords=[];chord=[];notes=set()
	for c in h:
		if c not in key_dict:continue
		n,f=key_dict[c]['note'],key_dict[c]['frequency']
		if n in notes:
			if chord:chords.append(chord)
			chord=[];notes=set()
		chord.append((n,f,c));notes.add(n)
	if chord:chords.append(chord)
	return chords

def save_audio(it,key_dict,out_file):
	sr=44100
	silence=zeros(int(0.01*sr),dtype=float32)
	with SoundFile(out_file,'w',sr,1,'PCM_16') as sf:
		for seg in it:
			for chord in gen_chords(seg,key_dict):
				freqs=[(f,0.08*(i+1)) for i,(_,f,_) in enumerate(chord)]
				w,_=gen_sound(freqs)
				sf.write(w);sf.write(silence)

def analyze_audio(file,f2k,allf,thr=0.05):
	try:
		with SoundFile(file,'r') as sf:
			ch,sr=sf.channels,sf.samplerate
			cs=int(0.1*sr);ss=int(0.01*sr);step=cs+ss
			while True:
				f=sf.read(step,dtype='float32',always_2d=False)
				if f is None or len(f)==0:break
				if ch>1:f=f[:,0]
				fi=(f*32767).astype(int16).astype(float32)
				if len(fi)<cs//2 or max(abs(fi))<100:continue
				seg=fi[:cs];w=seg*hanning(len(seg));fftv=rfft(w)
				m=abs(fftv)
				if max(m)<1e-9:continue
				m/=max(m)
				detected=[(f,m[int(round(f*len(seg)/sr))]) for f in allf if m[int(round(f*len(seg)/sr))]>=thr]
				if detected:yield [f2k[f] for f,_ in sorted(detected,key=lambda x:x[1])]
	except Exception as e:print(f'error: {e}')

def main():
	p=ArgumentParser(description='encrypt data using aes256-cbc and chorded fsk')
	sp=p.add_subparsers(dest='command',required=True)
	s=ArgumentParser(add_help=False)
	s.add_argument('--key',required=True,help='aes key (32 characters)')
	s.add_argument('--iv',required=True,help='initialization vector (16 characters)')
	e=sp.add_parser('encrypt',parents=[s],help='encrypt text to audio')
	e.add_argument('--text',help='text to encrypt')
	e.add_argument('--file',help='file to encrypt')
	e.add_argument('--output',required=True,help='output audio file (.flac, .wav or .aiff)')
	d=sp.add_parser('decrypt',parents=[s],help='decrypt audio to text')
	d.add_argument('--input',required=True,help='input audio file')
	d.add_argument('--file',action='store_true',help='extract as file')
	a=p.parse_args()
	if len(a.key)!=32:print('error: key must be 32 bytes');return
	if len(a.iv)!=16:print('error: iv must be 16 bytes');return
	k,f2k,allf=permute_freq_map(a.key.encode(),a.iv.encode())
	if a.command=='encrypt':
		if a.text and a.file:print('error: cannot use both --text and --file');return
		if not a.text and not a.file:print('error: specify --text or --file');return
		it=_text(a.text) if a.text else _file(a.file) if a.file and exists(a.file) else None
		if not it:print('error: specify --text or --file');return
		save_audio(_hex(it,a.key.encode(),a.iv.encode()),k,a.output)
		print('encrypted audio created')
	elif a.command=='decrypt':
		if not exists(a.input):print('error: input audio does not exist');return
		chords=analyze_audio(a.input,f2k,allf)
		hex_buf=''.join(k for c in chords for k in c)
		try:
			pt_bytes=decrypt(bytes.fromhex(hex_buf),a.key.encode(),a.iv.encode())
		except Exception as e:
			print(f'error: {e}');return
		if a.file:
			if b'\x00' in pt_bytes:
				name,data=pt_bytes.split(b'\x00',1)
				fname=name.decode('utf-8')
				ext=splitext(fname)[1].lower()
				if ext not in COMPRESSED_EXTS:
					try:data=decompress(data)
					except:pass
				with open(fname,'wb') as f:f.write(data)
				print(f'decypted file extracted: {fname}')
			else:
				print('error: decrypted content not a file')
				try:print(f'decrypted text: {pt_bytes.decode("utf-8")}')
				except:pass
		else:
			try:print(f'decrypted text: {pt_bytes.decode("utf-8")}')
			except:print('error: decrypted bytes are not valid utf-8')

if __name__=='__main__':main()
	# by azuk4r
	# ¬_¬
