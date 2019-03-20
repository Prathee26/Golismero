#!/usr/bin/python
# SCRIPT:           IEM_multiconsole_multiproc.py
# AUTHORs:          Mircea Paslaru/Romania/IBM, Denisa Bianca Limbosanu/Romania/IBM

# MAILs:            mircea.paslaru@ro.ibm.com 
# DATE:             2017-04-06  (YYYY-MM-DD)
# REV:              1.0.P (Valid are A, B, D, T and P)  # (For Alpha, Beta, Dev, Test and Production)
# PLATFORM:         Big Fix / SADB / APARDB / MAD / MDR / PUMA
# PREREQUISITES:    Windows OS, PRIVATE KEY to connect to the bulk list of servers, or user / passwd
# PURPOSE:          Script to extract data from various applications (Big Fix / SADB / APARDB / MAD / MDR / PUMA)
#                   Analysis the Big Fix baseline results
#                   Determines the fixlets applicability and closes the APARs
#                   Used for reporting purposes
#                   Handles every instance of the Big Fix console
#                   Used as backend for Security Operation Center
#                   Runs also in autonomous mode, providing data continuously from all the above applications
#                   The data is exposed through an API to be consumed by any other application



 

import sys
sys.path.append("c:\\Users\\Administrator\\Desktop\\Script\\")
import base64
from multiprocessing import Pool
import sqlite3
import numpy as np
from datetime import date,time,datetime,timedelta
import time
import csv
import pythoncom
import os
from subprocess import call
import re
import requests
import xml
from xml.dom import minidom
import ibm_db
from shutil import copyfile
import xml.etree.ElementTree as ET
from random import randint
import httplib2
import pprint
import simplejson
import json
from time import gmtime, strftime
from multiprocessing.dummy import Pool as ThreadPool
import urllib3
import pymysql
import pypyodbc
import socket
import datetime


 
No_of_days=25
No_of_chunks=No_of_days*8
#nr_of_predefined_jobs / No_of_chunks = 224 distinct chunks = 41 servers (82 scans)
#run interval: RO:20:00 --> 04:00  [IN 23:30 --> 07:30]
#run days of the month 01 --> 25

#input('Option: ',option)
option='u'
#option='ui'

enc_password='wrrDkMOmw5TDrMOYwrjCtMKFwpjClWVhdFTDgcKbwpjCi2o='
#enc_password_SADB_API='w43DjcOcw43DoMOZw6DDhmRn'
enc_password_funcID = 'wo_CjsK0w4XDpMOOw6XCmXbChsKGVkQ='

import warnings
if not sys.warnoptions:
    warnings.simplefilter("ignore")

print()
print('--------------------------------- New Launch --------------------------------')
print('Building database ...')
print('\n')


if os.path.exists('enc_key.txt'):
    with open('enc_key.txt','r') as fin:
        lines=fin.readlines()
    enc_key=lines[0].strip()
else:
    print('You need the key file for the Nessus 7 password. (mircea.paslaru@ro.ibm.com)')
    exit()
def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)

def post_payload(USERNAME,PASSWORD,baseurl):


    now=datetime.datetime.now()

    dth=now.strftime('%Y%m%d_%H%m%S%f')

    jsondata='{'+'''"username":"NessusAOSec2","password":"{}"'''.format(PASSWORD)+'}'
    with requests.Session() as s:
        s.verify=False

        headers = {'Content-Type': 'application/json'}

        r=s.post(baseurl,data=jsondata, headers=headers, auth=(USERNAME,PASSWORD))
        if r.status_code != 200:
            print ('Status code {}'.format(r.status_code))
        print()

        #print(json.loads(r.text)['token'])
    return json.loads(r.text)['token']


def get_xapitoken():

    #f=open('xapitoken.txt','w+')
    now=datetime.datetime.now()

    dth=now.strftime('%Y%m%d_%H%m%S%f')

    url="https://9.220.160.16:8834/nessus6.js?v=1529449192037"

    import requests
    response = requests.get(url,verify=False)
    rezult_page = str((response.text))
    file = open("tokenxapi.txt",'w',encoding='utf-8',newline='\n')
    file.write(rezult_page)
    sub='''f(a,[{key:"getApiToken",value:function(){return'''
    with open("tokenxapi.txt",encoding='utf-8') as fp:
        for i, line in enumerate(fp):
            #print(line)
            if(line.find(sub)!= -1):
                return (line[line.index(sub) + len(sub)+1:line.index(sub) + len(sub)+len("9B2B765E-2867-4DB0-9B60-EE8D0D1036EC")+1])    

print('Getting X-API-Token ...')

def get_jobs(X_Cookie,X_API_Token,baseurl):

    now=datetime.datetime.now()

    dth=now.strftime('%Y%m%d_%H%m%S%f')

    with requests.Session() as s:
        s.verify=False

        headers = {'X-Cookie': 'token='+X_Cookie,'X-API-Token' : X_API_Token}

        r=s.get(baseurl, headers=headers)
        if r.status_code != 200:
            print ('Status code {}'.format(r.status_code))
        print()

    return json.loads(r.text)['scans']

# def post_lastscan(fqdn,job_id):


#     now=datetime.datetime.now()

#     dth=now.strftime('%Y%m%d_%H%m%S')

#     jsondata='{'+'''"fqdn":"{}","last_scan_date":"{}","mail_id":"aosec@us.ibm.com","scan_history":"https://9.220.160.16:8834/#/scans/reports/{}"'''.format(fqdn,now,job_id)+'}'
#     #jsondata = {'fqdn': fqdn,'last_scan_date' : now, 'mail_id':'aosec@us.ibm.com'}

#     with requests.Session() as s:
#         s.verify=False

#         headers = {'Content-Type': 'application/json'}

#         r=s.post('https://mopbz171091.fr.dst.ibm.com:5000/nessus_scheduler_id',data=jsondata, headers=headers)
#         if r.status_code != 200:
#             print ('Status code {}'.format(r.status_code))
#         #print()

#         #print(json.loads(r.text))
#     #return json.loads(r.text)


def main(params):
    if(len(params) < 2):
        days_lost = 0
    if(len(params) == 2):
        days_lost = params[1]
    list_is_ready= False
    re_run= True
    while True:
        if option == 'u':
            hour_to_start='21'
            minute_to_start='00'            
        else:
            now=datetime.datetime.now() 
            hour=str('0'+str(now.hour) if now.hour<10 else str(now.hour))
            minute=str('0'+str(now.minute) if now.minute<10 else str(now.minute))                              
            hour_to_start=hour
            minute_to_start=minute
        print('waiting for {}'.format(hour_to_start+':'+minute_to_start+' ...'))
        while True:
            now=datetime.datetime.now()
            year=str(now.year)
            month=str('0'+str(now.month) if now.month<10 else str(now.month))
            day=str('0'+str(now.day) if now.day<10 else str(now.day))
            hour=str('0'+str(now.hour) if now.hour<10 else str(now.hour))
            minute=str('0'+str(now.minute) if now.minute<10 else str(now.minute))
            second=str('0'+str(now.second) if now.second<10 else str(now.second))
            dt=year+month+day
            th=year+month+day+'_'+hour+minute+second
            #print(hour,minute)
            if (day=='01' and not list_is_ready) or re_run:


                USERNAME='NessusAOSec2'
                PASSWORD=decode(enc_key,enc_password)
                baseurl = 'https://9.220.160.16:8834/session'
                X_Cookie=post_payload(USERNAME,PASSWORD,baseurl)
                #X_API_Token=get_xapitoken()
                #print(X_API_Token)
                #print("mai sus")
                X_API_Token='A8CB78F7-F75A-4B1F-9440-388C66A065F7' # <--------- DE SCHIMBAT
                baseurl='https://9.220.160.16:8834/scans/'
                jobs=get_jobs(X_Cookie, X_API_Token, baseurl)
                #print(jobs)  # list of dictionary
                jobs_dict_ids={}
                jobs_list=[]    #list with all the predefined jobs in Nessus 7
                for dct in jobs:
                    jobs_dict_ids[dct['name'].strip().lower()]=dct['id']
                    jobs_list.append(dct['name'].lower())   
                jobs_list.sort()
                scheduling_dict={}
                #make the scheduling_dict:
                # {(dd,hh),[fqdn1,...,fqdnx],
                #  (dd,hh),[fqdn1,...,fqdnx],
                # 
                #   ...
                # 
                #  (dd,hh),[fqdn1,...,fqdnx]}

                #No_of_days=25
                #No_of_chunks=No_of_days*8 = 200
                lines=No_of_chunks
                #len(jobs_list)=all fqdns defined in Nessus
                #len(jobs_list) // No_of_chunks = no of fqdns per chunks
                no_of_fqdns_per_chunks=len(jobs_list) // No_of_chunks
                columns=no_of_fqdns_per_chunks
                remainder = (len(jobs_list) % No_of_chunks)
                # columns=no_of_fqdns_per_chunks_exact         
                # jobs_list_resized = np.resize(np.array(jobs_list)(1,columns))
                # chunks_array=np.array(jobs_list_resized).reshape(lines,columns)
                # last_line=jobs_list[((lines-1)*columns)+1:].extend([' ']*(columns-remainder))
                # np.append(chunks_array,last_line)
                import sqlite3
                try:
                    conn = sqlite3.connect('SADBServers.db')
                    c = conn.cursor()
                except:
                    print ('Cannot connect to SADBServers.db')
                    return
                
                c.execute('''Create table if not exists Preconfigured_jobs  (ServerName text,
                                                                             Date_to_be_scanned text)''')
                c.execute(''' delete from preconfigured_jobs''')
                chunks_array = [['' for x in range(columns+1)] for y in range(200)]
                line = 0
                col = 0
                chunk_date = ['02','03','04','05','06','07','08','09','10','11','12','13','14','15','16','17','18','19','20','21','22','23','24','25','26']
                i = 1
                date_no = 0
                #try:
                for fqdn in jobs_list:
                    if line < 200:
                        if col < columns+1:
                            chunks_array[line][col] = fqdn
                            col = col +1
                            chunk_name = '{} {}'.format(chunk_date[date_no],month)
                            c.execute('INSERT INTO Preconfigured_jobs VALUES (?,?)',(fqdn,chunk_name,))
                        else:
                            line = line + 1
                            col = 0
                            chunks_array[line][col] = fqdn
                            chunk_name = '{} {}'.format(chunk_date[date_no],month)
                            c.execute('INSERT INTO Preconfigured_jobs VALUES (?,?)',(fqdn,chunk_name,))
                            if(i % 8 == 0):
                                date_no = date_no +1
                                i = 1
                            else:
                                i = i+ 1

                            
                # except : 
                #     print(line)
                #     print(col)
                conn.commit()
                print('Chunks array created')

                c.execute('''select * from preconfigured_jobs''')
                source=c.fetchall()
                with open('C:/Users/Administrator/Desktop/Nessus_Scheduller/Schedueler_list.csv','w',newline='',encoding='utf-8', errors='ignore') as Newly_commissioned :
                    writer = csv.writer(Newly_commissioned)
                    writer.writerow(['ServerName',
                                    'Date_to_be_scanned'])
                    writer.writerows(source)



                keys_list=[] #[(dd,hh), (dd,hh), .... , (dd,hh)]

                dd_tuple=('02','03','04','05','06','07','08','09','10','11','12','13','14','15','16','17','18','19','20','21','22','23','24','25','26')
                

                hh_tuple=('21','22','23','00','01','02','03','04')
                line_no=0
                try:
                    for dd in dd_tuple:
                        for hh in hh_tuple:            
                    
                            scheduling_dict[(dd,hh)]=list(chunks_array[line_no])
                            line_no=line_no+1
                except:
                    print(line_no)
                print('Dictionary created')
                if(re_run):
                    day_to_be_recovered = int(day) - int(days_lost)
                    while str(day_to_be_recovered) < day:
                        for hh in hh_tuple:
                            scheduling_list = scheduling_dict[(str(day_to_be_recovered),hh)]
                            for fqdn in scheduling_list:
                                #os.system('Nessus7Launcher_ver1.py {}'.format(fqdn))
                                # try:
                                #     post_lastscan(fqdn)
                                # except:
                                #     print('''{} not written to the Nessus_scans table'''.format(fqdn))
                                scheduling_dict[(dd,hh)][0]='done'
                            
                        print('Launch done for day {} and hour {}'.format(day,hour))
                        day_to_be_recovered +=1
                list_is_ready=True
                re_run= False
            i = 0
            if '02'<=day<='26' and  hour in ('21','22','23','00','01','02','03','04'):
                dd=day
                hh=hour
                scheduling_list = scheduling_dict[(dd,hh)]
                if scheduling_dict[(dd,hh)][0]=='done':
                    continue            
                else:
                    #launch scan for scheduling_dict[(dd,hh)] chunk
                    for fqdn in scheduling_list:
                        # call_launch="Nessus7Launcher_ver1.0.py "+fqdn
                        # print(call_launch)
                        # call(call_launch) 
                        #launch.main(fqdn)
                        #print(fqdn)
                        #os.system('Nessus7Launcher_ver1.py {}'.format(fqdn))
                        # try:
                        #     post_lastscan(fqdn)
                        # except:
                        #     print('''{} not written to the Nessus_scans table'''.format(fqdn))
                        print(i)
                        i = i+1
                        #call('Nessus7Launcher_ver1.py {}'.format(fqdn), shell=True)
                    scheduling_dict[(dd,hh)][0]='done'
                print('Launch done for day {} and hour {}'.format(day,hour))



            if day=='27':
                path = r'C:\Users\Administrator\Desktop\Nessus_Scheduller'
                new_path = r'C:\Users\Administrator\Desktop\Nessus_Scheduller\old_target_jobs'   
                allFiles = os.listdir(path)
                for fname in allFiles:
                    if (fname.find('target_jobs_file2') != -1):
                         source_path = path + '\\' + fname
                         destination_path = new_path + '\\' + fname
                         os.rename(source_path,destination_path)                 
                list_is_ready=False
params = sys.argv
if __name__ == "__main__": main(params)
