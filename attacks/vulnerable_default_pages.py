#!/usr/bin/pyton3
from termcolor import colored
from  urllib.parse import urlparse
import requests


#design function 
def f():
	#print('       ',end='')
	print(colored(' '*173,'white','on_grey',['blink','dark']))

	
#/usr/share/wordlists/dirb/vulns
def vulnerable_pages(url):
	try:
		urlparsed=urlparse(url)
		url=urlparsed.scheme+'://'+urlparsed.netloc
		file_pointer=open('payloads/vulnerable_default_pages.txt')
		reading_file=file_pointer.readlines()
		for line in reading_file:
			line=line.strip('\n')
			try:
				print(colored('\r[!] TRYING FOR VULNEARBLE PAGE --> '+url+'/'+line,'green'),flush=True,end='')
				#time.sleep(0.1)
				res=requests.get(url+'/'+line)
				if(res.status_code==200):
					print(colored('\r[+] FOUND VULNEARBLE PAGE (DEFAULT PAGE) --> '+url+'/'+line,'red',attrs=['bold']))
			except Exception as e:
				print(colored("\r[!] PAGE NOT FOUND -->"+url+'/'+line,'red'),flush=True,end='')
	except KeyboardInterrupt:
		f()
		print(colored('[-] KEYBOARD INTERRUPT CTRL+ C PRESSED ','red'))
		f()
	except Exception as e:
		print((colored('[-]'+str(e),'red')))