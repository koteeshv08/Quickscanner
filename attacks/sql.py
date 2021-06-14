import requests as s
import sys
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
from pprint import pprint
from termcolor import colored
import time
import threading
from  urllib.parse import urlparse



def get_all_forms(url,cookies):
    """Given a `url`, it returns all forms from the HTML content"""
    try:
    	soup = bs(s.get(url,cookies=cookies).content, "html.parser")
    	return soup.find_all("form")
    except Exception as e:
    	print(colored(e,'red'))
    

def get_form_details(form):
    """
    This function extracts all possible useful information about an HTML `form`
    """
    details = {}
    # get the form action (target url)
    try:
        action = form.attrs.get("action").lower()
    except:
        action = None
    # get the form method (POST, GET, etc.)
    method = form.attrs.get("method", "get").lower()
    # get all the input details such as type and name
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({"type": input_type, "name": input_name, "value": input_value})
    # put everything to the resulting dictionary
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details


def is_vulnerable(response):
    """A simple boolean function that determines whether a page 
    is SQL Injection vulnerable from its `response`"""
    errors = {
        # MySQL
        "you have an error in your sql syntax;",
        "warning: mysql",
        # SQL Server
        "unclosed quotation mark after the character string",
        # Oracle
        "quoted string not properly terminated",
    }
    for error in errors:
        # if you find one of these errors, return True
        #print(bs(response.text))
        if error in response.content.decode().lower():
        #if error in respone.text.lower():
            return True
    # no error detected
    return False


def scan_sql_injection(url,cookies):
    # test on URL
    for c in "\"'":
        # add quote/double quote character to the URL
        new_url = f"{url}{c}"
        print(colored("[!] Trying for "+new_url,'green'))
        # make the HTTP request
        res = s.get(new_url,cookies=cookies)
        if is_vulnerable(res):
            # SQL Injection detected on the URL itself, 
            # no need to preceed for extracting forms and submitting them
            print(colored("[+] SQL Injection vulnerability detected, link:"+str(new_url),'red'))
            return
    # test on HTML forms
    forms = get_all_forms(url,cookies)
    #print(colored(f"[+] Detected {len(forms)} forms on {url}.",'yellow'))
    for form in forms:
        form_details = get_form_details(form)
        #print(colored(form_details,'red'))
        for c in "\"'":
            # the data body we want to submit
            data = {}
            for input_tag in form_details["inputs"]:
                if input_tag["value"] or input_tag["type"] == "hidden":
                    # any input form that has some value or hidden,
                    # just use it in the form body
                    try:
                        data[input_tag["name"]] = input_tag["value"] + c
                    except:
                        pass
                elif input_tag["type"] != "submit":
                    # all others except submit, use some junk data with special character
                    data[input_tag["name"]] = f"test{c}"
            # join the url with the action (form request URL)
            url = urljoin(url, form_details["action"])
            #print(url)
            #print(data)
            if form_details["method"] == "post":
                res = s.post(url, data=data,cookies=cookies)
            elif form_details["method"] == "get":
                res = s.get(url, params=data,cookies=cookies)
            # test whether the resulting page is vulnerable
            if is_vulnerable(res):
                print(colored("[+] SQL Injection vulnerability detected, link:"+str(url),'red',attrs=['bold']))
                #print("[+] Form:")
                #pprint(form_details)
                break   

