import requests
from pprint import pprint
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
from termcolor import colored


xss_list=[] 
def get_all_forms(url,cookies):
    soup=bs(requests.get(url,cookies=cookies).content, "html.parser")
    return soup.find_all("form")


def get_form_details(form):
    details = {}
    try:
        action = form.attrs.get("action")
    except:
        action = None
    # get the form method (POST, GET, etc.)
    method = form.attrs.get("method", "get").lower()
    # get all the input details such as type and name
    #type=button , submit , textarea , option 
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({"type": input_type, "name": input_name, "value": input_value})
    for textarea_tag in form.find_all('textarea'):
        input_name=textarea_tag.attrs.get('name')
        input_value=textarea_tag.attrs.get('value')
        if not (input_value):
            input_value=''
        input_type='text'
        if  (input_name):
            inputs.append({"type":input_type,"name": input_name,"value":input_value})
    for button_tag in form.find_all('button'):
        input_name=button_tag.attrs.get('name')
        input_value=button_tag.attrs.get('value')
        input_type=button_tag.attrs.get('type')
        if(input_type.lower()=='submit' and input_name):
            inputs.append({"name": input_name,"value":input_value,'type':'button_submit'})
    for select in form.find_all('select'):
        input_name=select.attrs.get('name')
        for option in select.find_all('option'):
            if(option.attrs.get('name')):
                input_value=option.attrs.get('name')
                break
        if  (input_name):
            inputs.append({"name": input_name,"value":input_value,'type':'select'})


    # put everything to the resulting dictionary
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

def submit_form(form_details, url,payload,cookies):
    target_url = urljoin(url,form_details["action"])
    inputs = form_details["inputs"]
    data={}
    for input in inputs:
        #print(inputs)
        if input["type"] == "text" or input["type"] =="search":
            input["value"] = payload
        input_name = input.get("name")
        input_value=input.get("value")

        if input_name and input_value:
            data[input_name]=input_value

    if form_details["method"] == "post":
        return requests.post(target_url, data=data,cookies=cookies) , data 

    else:
        return requests.get(target_url,params=data,cookies=cookies) , data

def scan_xss(url,cookies):

    global xss_list
    forms = get_all_forms(url,cookies)
    #print(f"[+] Detected {len(forms)} forms on {url}.")
    f=open("payloads/xss.txt",'r')
    for line in f.readlines():
        payload=line.strip('\n')
        is_vulnerable = False
        # iterate over all forms
        for form in forms:
            form_details = get_form_details(form)
            res,data  = submit_form(form_details, url, payload,cookies)
            content=res.content.decode()
            if payload in content or payload in requests.get(url,cookies=cookies).content.decode():
                #print(payload)
                print(colored("\r[+] XSS CROSS SITE SCRIPTING VULNERABILITY DETECTED  -->  "+str(url),'red',attrs=['bold']),colored('\n[*] FORM DATA :  '+str(data),'white',attrs=['dark','bold']))
                xss_dict={'url':url,'method':form_details['method'],'payload':payload,'data':data}
                xss_list.append(xss_dict)
                #print(f"[+] XSS Detected on {url}")
                #print(f"[*] Form details:")
                #pprint(form_details)
                #is_vulnerable = True
                #return is_vulnerable
                # won't break because we want to print available vulnerable forms
                return

