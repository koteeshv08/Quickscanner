#!/usr/bin/python3
#
#
#
#
#
#
#
#
#  This is a python based tool to scan for Vulnerabilities in any Web Application 
#  mainly it is focused  to determine the Top10 OWASP Vulnerabilities in web app...
#
#
#


#import libraries 
import os
import re
import sys
import yaml
import time
import requests
import builtwith
import threading
import urllib.request 
from argparse import *
from parsel import Selector
from termcolor import colored
from  urllib.parse import urlparse
from attacks import vulnerable_default_pages
from attacks import sql

#define variables
url=''
threads=1
output='txt'
cookies={}
validcookie=False

#banner function
def banner():
	print(colored(""" 
				                                                                    
				    $$$$$                       $$  $$      $$$$$                 
				   $$   $$  $$   $$  **   $$$$  $$ $$      $$       $$$$   $$$$     $ $$$$$
				   $$   $$  $$   $$  $$  $$     $$$         $$$$   $$     $$  $$     $$   $$
				   $$  $$$  $$   $$  $$  $$     $$ $$          $$  $$     $$  $$     $$   $$
  				    $$$$$$   $$$$$   $$   $$$$  $$  $$     $$$$$    $$$$   $$$$$$$   $$   $$
				    	 $$                                                                                         """,'blue'))
	print(colored("""                                                       ( Web Vulnerability Scanner )
							     Author : Prajwal A """,'yellow'))
	print(colored("""						Github : https://github.com/prajwalcbk/Quickscanner""",'white',attrs=['dark']))


#help function
def helper():
		print(colored("USAGE OF THE PROGRAM",'blue'))
		print(colored("--------------------",'yellow'))
		print(colored("         python3 main.py -u <url> -t <threads> -o <output> -c <cookie> -p <single_page> ",'red'))
		print(colored("\n         Ex: python3 main.py -u http://msrit.edu (-p http://msrit.edu/index.php) -t 2 -o txt -c \"{\'phpsessionid\':\'1234\'}\" ",'cyan',attrs=['dark']))
		print(colored("\nOPTIONS",'blue'))
		print(colored("-------",'yellow'))
		print(colored('''        -u --url     --> URL of the target website to scan    Ex: http://website.com
	-t --threads --> Threads  to  execute  python code    Ex: 1 2 3 
	-o --output  --> Output  format of Report to save     Ex: txt html console default(console)
	-c --cookie  --> Cookies after target website login   Ex: "{'key':'value','key1':'value1'}" 
	-p --page    --> Single page checking No crawl        Ex: http://website.com/index.html ''','green'))
		print(colored("\n\nINTERACTION",'blue'))
		print(colored('-----------','yellow'))
		print(colored('         CTRL+C to quit the program','green'))
	
		print(colored("\n\nDESCRIPTION",'blue'))
		print(colored("-----------",'yellow'))
		print(colored('''          This is a python based tool to scan for Vulnerabilities in any Web Application 
	  mainly it is focused  to determine the Top10 OWASP Vulnerabilities in web app...\n''','green'))



#Overide the error method in ArgumentParser
class MyParser(ArgumentParser):
	def error(self, message):
		print(colored("[-] "+message+'\n','red'))
		helper()
		sys.exit(2)



#Argument passing taking inputs from the terminal
def create_argument_parser():
	try:
		parser=MyParser(add_help=False)
		parser.add_argument('-u','--url',dest='url',required=False)
		parser.add_argument('-t','--threads',dest='threads',required=False,default='1')
		parser.add_argument('-o','--output',dest='output',required=False,default='console')
		parser.add_argument('-p','--page',dest='page',required=False,default='')
		parser.add_argument('-c','--cookie',dest='cookies',required=False,default={},type=yaml.safe_load)
		return parser.parse_args()
	except Exception as e:
		print(colored(e,'red'))
		helper()


#function to check internet connectivity
#0 stdin 1 stdout 2 stderr
def internet_check():
	try:
		num=os.system('ping -c 1 google.com > internet.txt 2>&1')
		file_pointer=open('internet.txt')
		content=file_pointer.read()
		file_pointer.close()
		os.system('rm internet.txt')
		if not "0% packet loss" in content:
			print(colored('[-] NO INTERNET CONNECT TO NETWORK AND TRY AGAIN','red'))
			print(colored('[+] IF YOU CONNECTED TO NETWORK PLEASE TRY AGAIN','yellow'))
			f()
			sys.exit(0)
		else:
			print(colored('[+] HAVING STABLE INTERNET CONNECTION','green'))
	except KeyboardInterrupt:
		f()
		print(colored('[-] KEYBOARD INTERRUPT CTRL+ C PRESSED ','red'))
		f()
		sys.exit(0)
	except Exception as e:
		print(colored(e,'red'))
		f()



#function to check given url to valid or notd 
def url_check():
	try:
		if not re.match(r'http(s?)\:\/\/', url):
			print(colored('[-] ENTER THE CORRECT URL OF THE TARGET','red'))
			f()
			helper()
			sys.exit(0)
		else:
			print(colored('[+] URL IS VALID','green'))
	except KeyboardInterrupt:
		f()
		print(colored('[-] KEYBOARD INTERRUPT CTRL+ C PRESSED ','red'))
		f()
		sys.exit(0)
	except Exception as e:
		print(colored(e,'red'))



#function to check cookie is valid or not 
def cookie_check():
	try:
		#print(colored(input_url,'red'))
		#print(colored(cookies,'red'))
		response1=requests.get(input_url,cookies=cookies,timeout=5)
		response2=requests.get(input_url,timeout=5)
		if('Content-Length' in response1.headers and 'Content-Length' in response2.headers):	
			if not (response1.headers['Content-Length']==response2.headers['Content-Length']):
				print(colored("[+] VALID COOKIE",'green'))
				validcookie=True
			else:
				print(colored("[-]INVALID COOKIE",'red'))
		else:
			#print(response1.text)
			#print(response2.text)
			if(response1.text!=response2.text):
				print(colored("[+] VALID COOKIE",'green'))
				validcookie=True
			else:
				print(colored("[-] INVALID COOKIE",'red'))
	except KeyboardInterrupt:
		f()
		print(colored('[-] KEYBOARD INTERRUPT CTRL+ C PRESSED ','red'))
		f()
		sys.exit(0)
	except Exception as e:
		print(colored(e,'red'))
		print(colored('[-] TARGET IS NOT REACHABLE WITH THAT COOKIE CHECK URL ','red'))

		
	


#function to know target is reachable or not
def host_reachable():
	try:
		status_code = urllib.request.urlopen(url,timeout=5).getcode()
		if(status_code == 200):
			print(colored('[+] TARGET IS REACHABLE ','green'))
		else:
			print(colored('[-] TARGET IS NOT REACHABLE CHECK URL ','red'))
			f()
			sys.exit(0)
	except KeyboardInterrupt:
		f()
		print(colored('[-] KEYBOARD INTERRUPT CTRL+ C PRESSED ','red'))
		f()
		sys.exit(0)
	except Exception as e:
		print(colored('[-] '+str(e),'red'))
		print(colored('[-] TARGET IS NOT REACHABLE CHECK URL ','red'))
		f()
		sys.exit(0)

#function to gather information about the Target website
def information_gathering():
	try:
		response=requests.get(url,timeout=5)
		if('server' in response.headers):
			print(colored("[+]  SERVER      --> "+response.headers['server'],'green'))
		if('X-Powered-By' in response.headers):
			print(colored("[+]  X-Powered-By--> "+response.headers['X-Powered-By'],'green'))
		if('Connection' in response.headers):
			print(colored("[+]  CONNECTION   -> "+response.headers['Connection'],'green'))
		if('Content-Type' in response.headers):
			print(colored("[+]  CONTENT-TYPE -> "+response.headers['Content-Type'],'green'))
	except KeyboardInterrupt:
		f()
		print(colored('[-] KEYBOARD INTERRUPT CTRL+ C PRESSED ','red'))
		f()
		sys.exit(0)
	except Exception as e:
		print((colored('[-]'+str(e),'red')))
		print(colored('[-] EXCEPTION OCCURED WHILE GATHERING TARGET INFORMATION ','red'))

#function to spider crawl over the target website 
links_list=[]
target_path=[]
target_links=[]
target_photos=[]
target_photos_dict={}

def spider_links(myurl,mycookies={}):
	try:
    		if(re.match(r'http(s?).*logout.*',myurl)):
    		#if we logout from the session we will miss some pages
    			links_list.append(myurl)
    		if(myurl not in links_list):
	        	response=requests.get(myurl,timeout=5,cookies=mycookies)
		        if(response.status_code!=200):
		        	return
		        print(colored("[*] SPIDERING [+] GOT SOME PAGE  -->  "+myurl,'green'))
		        links_list.append(myurl)
		        if(page==myurl):
		        	return
		        select=Selector(response.text)
		        links=select.xpath('//a/@href').getall()
		        directories=select.xpath('//img/@src').getall()
		        temp=[]
		        for i in directories:
		        	if(len(i)<100 and i not in target_photos):#or re.match(r'data:image/jpeg;base64.*',i)):
		        		target_photos.append(i)
		        		temp.append(i)
		        if(temp!=[]):
		        	target_photos_dict[myurl]=temp
		        s=set(links)
		        links=list(s)
		        for link in links:
		        	if(len(link)<=0):
		        		continue
		        	#link=link.strip('/')
		        	#print(link)
		        	if re.match(r'#.*',link):
		        		#no need to check for fragments so skip
		        		continue
		        	if urlparse(link).netloc!='' or '.com' in link:
		        		if(re.match(r'http(s?).*\.com',urlparse(link).netloc) or re.match(r'.*\.com',link)):#urlparse(link).netloc)):
		        		#illgeal to do crawl on .com websites
		        			print(colored('[-].COM WEBSITE GOT SKIP         -->  '+link,'white',attrs=['dark']))	
		        			#print(colored('[-]                              --> '+link,'red'))
		        			continue
		        	if re.match(r'http(s?).*\.in',link):
		        		#illgeal to do crawl on .in websites
		        		print(colored('[-].IN WEBSITE GOT SKIP              -->'+link,'white',attrs=['dark']))
		        		continue
		        	if re.match(r'http(s?).*\.pdf',link):
		        		#If we got pdf link then no crawl
		        		print(colored('[-].PDF FILE GOT SKIP                -->'+link,'white',attrs=['dark']))
		        		continue
		        	if re.match(r'http(s?).*\.jpg',link) or re.match(r'http(s?).*\.jpeg',link) or re.match(r'http(s?).*\.png',link) or re.match(r'.*\.png',link):
		        		#if we got jpg files then no need to crawl
		        		print(colored('[-] IMAGE FILE GOT SKIP              -->'+link,'white',attrs=['dark']))
		        		continue
		        	if re.match(r'http(s?)\:\/\/.*',link):
		        		if not re.match(url+'.*',link):
		        			print(colored('[-] GOT SOME OTHER WEBSITE LINK  -->  '+link,'white',attrs=['dark']))
		        			continue
		        	if not re.match(r'http(s?)\:\/\/',link):
		        		#If we got link with protocol and path no need to add any thing 
		        		#if re.match(r'.*.com')
		        		#print(myurl)
		        		#print(colored(link,'blue'))
		        		if(len(link)>=2):
		        			if(link[0]=='.' and link[1]=='/' ):
		        				link=link[2:]


		        		if(link[0]=='/'):
		        			#print(colored(link[0],'blue'))
		        			link=url+link
		        		
		        		else:
			        		u_link_parse=urlparse(response.url).path
			        		u_link_parse=u_link_parse.lstrip('/')
			        		u_link_parse=u_link_parse.split('/')
			        		count=len(u_link_parse)
			        		if('../' in link):
			        			counter=link.count('../')
			        			link=link.strip('../')
			        			if(counter==1):
			        				link=url+'/'+link
			        			elif(counter>=2):
			        				temp_link=url
			        				for i in range(counter-1):
			        					temp_link+='/'+u_link_parse[i]
			        				link=temp_link+'/'+link
			        		elif(count==0 or count==1):
			        			link=url+'/'+link
			        		elif(count>=2):
			        			extra_link=url
			        			for i in range(count-1):
			        				extra_link+='/'+u_link_parse[i]
			        			link=extra_link+'/'+link

		        	if(link in links_list):
		        		#if it is already crawled then no need to do once more
		        		continue
		        	print(colored('[*] SPIDER FOR LINK              -->  '+link,'yellow'))
		        	spider_links(link,mycookies)
	except Exception as e:
		print(colored(e,'red'))
		print(colored(links,'blue'))
		pass

	


#function to print the link which we are targeting
def print_target_links():
	try:
		print(colored('[+] PAGES GOT AFTER SPIDERING AND CRAWLING ','yellow'))
		#for i in links_list:
			#print(colored('     '+i,'blue'))
		print(colored('[*] TARGET LINKS STORED INSIDE   --> target.txt(Inside report)','cyan',attrs=['bold']))
		for i in links_list:
			single_link_parsing=urlparse(i)
			if(single_link_parsing.query):
				query_url=single_link_parsing.query
				query_list=query_url.split('&')
				#for k in query_list:
				#	i1=k.split('=')
				#	if(i1[1].isnumeric()):
				#		continue
			if(single_link_parsing.path+'?'+single_link_parsing.query not in target_path):
				target_path.append(single_link_parsing.path)
				target_links.append(i)
		target_file=open('report/target.txt','w')
		for j in target_links:
			target_file.write(j+'\n')
			print(colored('[!!] WE CAN TARGET ON THIS LINK  -->  '+j,'red',attrs=['dark','bold']))
		target_file.close()
	except KeyboardInterrupt:
		f()
		print(colored('[-] KEYBOARD INTERRUPT CTRL+ C PRESSED ','red'))
		f()
		sys.exit(0)
	except Exception as e:
		print((colored('[-]'+str(e),'red')))




#design function 
def f():
	print(colored(' '*170,'white','on_grey',['blink','dark']))




#main function 
def main():
	try:
		f()
		print(colored('[*] CHECKING FOR INTERNET CONNECTION','yellow'))
		internet_check()
		f()
		print(colored('[*] CHECKING VALID URL OR NOT ','yellow'))
		url_check()
		f()
		print(colored('[*] CHECKING TARGET IS REACHABLE OR NOT','yellow'))
		host_reachable()
		f()
		if not (cookies=={}):
			print(colored("[*] CHECKING VALID COOKIE OR NOT ",'yellow'))
			cookie_check()
			f()
		print(colored('[*] GATHERING INFORMATION ABOUT THE TARGET','yellow'))
		information_gathering()
		f()
		print(colored('[!] DO YOU WANT TO CRAWL THE WEBSITE TYPE [Y/n]','blue'),end='')
		yes_or_no=input()
		if(yes_or_no=='Y' or yes_or_no==''):
			print(colored('[*] SPIDERING AND WEB CRAWLING THE TARGET WEBSITE','yellow'))
			spider_links(url,cookies)
			if(validcookie==True):
				spider_links(url)
			f()
			print_target_links()
			f()
			print(colored('[!!] GOT SOME IMAGES INSIDE WEBSITE ','yellow'))
			print(colored('[*] SOME IMAGES OUTSIDE WEBSITES -->  photos.txt(links stored in this file)','cyan',attrs=['bold']))
			link_file_pointer=open('report/photos.txt','w')
			for photos in target_photos_dict:
				for photos_photos in target_photos_dict[photos]:
					if (re.match(r'http(s?).*',photos_photos)):
						link_file_pointer.write(photos_photos)
						continue #we have to include this in report 
					else:
						print(colored('[!] SOME IMAGES INSIDE WEBSITE   -->  '+photos_photos,'red'))
			f()
		else:
			f()
		print(colored('[!] DO YOU WANT TO CHECK FOR DEFAULT VULNEARBLE WEB PAGES TYPE [Y/n]','blue'),end='')
		yes_or_no=input()
		if(yes_or_no=='Y' or yes_or_no==''):
			print(colored('[*] CHEKING TARGET WEBSITE FOR DEFAULT VULNEARBLE PAGES','yellow'))
			vulnerable_default_pages.vulnerable_pages(url)
			print('\r',flush=True,end='')
			f()
		else:
			f()
		try:
			print(colored('[!] DO YOU WANT TO CHECK FOR SQL INJECTION TYPE [Y/n]','blue'),end='')
			yes_or_no=input()
			if(yes_or_no=='Y'or yes_or_no==''):
				for i in target_links:
					u=urlparse(i)
					if(len(u.path)==0):
						continue
					t=threading.Thread(target=sql.scan_sql_injection,args=(i,))
					t.start()
			t.join()
		except Exception as e:
			print(colored(e,'red'))
	except KeyboardInterrupt:
		f()
		print(colored('[-] KEYBOARD INTERRUPT CTRL+ C PRESSED ','red'))
		f()
	except Exception as e:
		print(colored(e,'red'))



#starting point of Code
if __name__=='__main__':
	try:
		start_time=time.time()
		os.system('mkdir report > error.logs 2>&1')
		banner()
		print('\n')
		parser=create_argument_parser()
		if(parser.url==None and parser.page==''):
			print(colored("[-] Enter Url or Website Page of the target \n",'red'))
			helper()
			sys.exit(0)
		else:
			page=parser.page
			if(page!=''):
				url=page
				input_url=page
				if(page[-1]=='/'):
					page=page[:-1]
			else:
				url=parser.url
				input_url=url
				urlparsed=urlparse(url)
				url=urlparsed.scheme+'://'+urlparsed.netloc
			if (url[-1]=='/'):
				url=url[:-1]
			if(parser.threads.isnumeric()==False):
				print(colored("[-] Enter threads in digits \n",'red'))
				helper()
				sys.exit(0)
			threads=int(parser.threads)
			if(not(parser.output=='txt' or parser.output=='html' or parser.output=='console')):
				helper()
				sys.exit(0)
			output=parser.output
			cookies=parser.cookies
		main()
		end_time=time.time()
		f()
		print(colored('[**] TIME TAKEN TO EXECUTE THE CODE '+str(end_time-start_time)+ " SECONDS",'yellow'))
		f()
	except KeyboardInterrupt:
		f()
		print(colored('[-] KEYBOARD INTERRUPT CTRL+ C PRESSED ','red'))
		f()
	except Exception as e:
		print(colored(e,'red'))
