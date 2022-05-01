from typing import get_args
import requests
import urllib3
import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def getHumanDate(epoch):
    try:
        epoch = time.strftime("%d %m %Y %H:%M:%S", time.localtime(int(epoch)))
        listEpoc = str(epoch).split(' ')
        return listEpoc
    except Exception as e:
        print(e, epoch)

def getScans(XSecurityCenterHeader, cookie):
    headers = {
        'Cookie': cookie,
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0',
        'X-SecurityCenter': str(XSecurityCenterHeader)
    }
    url = 'https://192.168.48.42'
    pathAllScans = '/rest/scanResult?startTime=1&filter=usable&optimizeCompletedScans=true&fields=canUse%2CcanManage%2Cowner%2Cgroups%2CownerGroup%2Cstatus%2Cname%2Cdetails%2CdiagnosticAvailable%2CimportStatus%2CcreatedTime%2CstartTime%2CfinishTime%2CimportStart%2CimportFinish%2Crunning%2CtotalIPs%2CscannedIPs%2CcompletedIPs%2CcompletedChecks%2CtotalChecks%2CdataFormat%2CdownloadAvailable%2CdownloadFormat%2Crepository%2CresultType%2CresultSource%2CscanDuration%2CSCI%2CsciOrganization%2CresultsSyncID%2CretrievalStatus'
    scans = requests.get(url+pathAllScans, headers=headers, verify=False)
    return scans

def deleteScan(XSecurityCenterHeader, cookie, idScan):
    headers = {
        'Cookie': cookie,
        'X-SecurityCenter': str(XSecurityCenterHeader),
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0',        
        'Accept-Language': 'en-US,es-ES;q=0.8,es;q=0.5,en;q=0.3'
    }
    url = 'https://192.168.48.42'
    pathAllScans = f'/rest/scanResult/{idScan}'
    delete = requests.delete(url+pathAllScans, headers=headers, verify=False)
    if delete.status_code == 200:
        return 'Deleted'
    return 'Saved'

def flyScans(monthStart, yearStart, XSecurityCenterHeader, cookie):
    scans = getScans(XSecurityCenterHeader, cookie)
    if scans.status_code == 200:
        count = 0
        for scan in scans.json()['response']['usable']:
            count += 1
            if scan['finishTime'] != '-1':
                scanDate = getHumanDate(scan['finishTime'])
            else:
                scanDate = ['13', '07', '2021', '13:26:39']
                        
            if int(scanDate[2]) < int(yearStart):
                print(f"Count: {count}\t{scan['id']}\t{scan['name']}\t{scanDate}\t{deleteScan(XSecurityCenterHeader, cookie, scan['id'])}")
            elif int(scanDate[2]) == int(yearStart) and int(scanDate[1]) <= int(monthStart):
                print(f"Count: {count}\t{scan['id']}\t{scan['name']}\t{scanDate}\t{deleteScan(XSecurityCenterHeader, cookie, scan['id'])}")
            else:
                print(f"Count: {count}\t{scan['id']}\t{scan['name']}\t{scanDate}\tDate not apply")

if __name__ == '__main__':
    monthStart = 9
    yearStart = 2021
    XSecurityCenterHeader = 264077450
    cookie = 'cookie_session_in_tenable_SC'
    flyScans(monthStart, yearStart, XSecurityCenterHeader, cookie) 
