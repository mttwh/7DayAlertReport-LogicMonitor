import logging
import requests
import json
import hashlib
import base64
import time
import hmac
import csv
from datetime import datetime, timedelta, timezone
import urllib.request
import azure.functions as func
from azure.storage.blob import BlobServiceClient


def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')

    accessId = req.params.get('accessId')
    accessKey = req.params.get('accessKey')
    lmCompany = req.params.get('lmCompany')
    if not accessId:
        try:
            req_body = req.get_json()
        except ValueError:
            pass
        else:
            accessId = req_body.get('accessId')
            accessKey = req_body.get('accessKey')
            lmCompany = req_body.get('lmCompany')

    #beginning of python script to grab alerts
    daysOfAlerts = 7
    dayCounter = 1
    daysOfAlerts = int(daysOfAlerts)
    lowerBoundValue = daysOfAlerts
    dayDecrementer = 1
    upperBoundValue = lowerBoundValue - dayDecrementer
    reportIdList = []

    #run a report of all alerts triggered during the amount of days specified in the params
    while dayCounter <= daysOfAlerts:
        formattedLowerBoundDate = (datetime.now() - timedelta(lowerBoundValue)).strftime('%Y-%m-%d %H:%M')
        formattedUpperBoundDate = (datetime.now() - timedelta(upperBoundValue)).strftime('%Y-%m-%d %H:%M')
        
        #Request Info to generate alerts
        httpVerb ='POST'
        resourcePath = '/report/reports'
        
        #report is defined in the data variable, including what columns are displayed
        data = '{"type":"Alert","groupId":0,"name":"' + str(lowerBoundValue) + ' Day Report - Part ' + str(dayCounter) + ' - Date: ' + str(formattedLowerBoundDate) + '","includePreexist":false,"sdtFilter":"nonsdt","timing":"start","dateRange":"' + formattedLowerBoundDate + ' TO ' + formattedUpperBoundDate + '","format":"CSV","description":"Series of reports to get all alerts triggered in the past 30 days.","delivery":"none","groupFullPath":"*","level":"all","activeOnly":false,"columns":[{"name":"Severity","isHidden":false},{"name":"Device","isHidden":false},{"name":"Datasource","isHidden":false},{"name":"Instance","isHidden":false},{"name":"Datapoint","isHidden":false},{"name":"Value","isHidden":true},{"name":"Began","isHidden":false},{"name":"Group","isHidden":false},{"name":"Thresholds","isHidden":true},{"name":"End","isHidden":true},{"name":"Rule","isHidden":true},{"name":"Chain","isHidden":true},{"name":"Acked","isHidden":true},{"name":"Acked By","isHidden":true},{"name":"Acked On","isHidden":true},{"name":"Notes","isHidden":true},{"name":"In SDT","isHidden":true}]}'
        lowerBoundValue -= dayDecrementer
        upperBoundValue -= dayDecrementer
        dayCounter +=1
        url = 'https://'+ lmCompany +'.logicmonitor.com/santaba/rest' + resourcePath 
        epoch = str(int(time.time() * 1000))
        requestVars = httpVerb + epoch + data + resourcePath
        hmac1 = hmac.new(accessKey.encode(),msg=requestVars.encode(),digestmod=hashlib.sha256).hexdigest()
        signature = base64.b64encode(hmac1.encode())
        auth = 'LMv1 ' + accessId + ':' + signature.decode() + ':' + epoch
        headers = {'Content-Type':'application/json','Authorization':auth}

        #Make request to generate reports, format response as JSON, and grab the report IDs
        response = requests.post(url, data=data, headers=headers)
        data = json.loads(response.content)
        reportId = data["data"]["id"]
        reportIdList.append(reportId)    

    logging.info("Reports successfully generated. Running reports...")

    #Placeholder list that alerts from all reports will be appended to
    masterList = []
    reportCounter = 1

    #run each report that was generated earlier and parse results. Append results to master list
    for reportId in reportIdList:
        runReporthttpVerb ='POST'
        runReportresourcePath = '/functions'
        runReportdata = '{"type":"generateReport","reportId":' + str(reportId) + '}'
        runReporturl = 'https://'+ lmCompany +'.logicmonitor.com/santaba/rest' + runReportresourcePath
        runReportepoch = str(int(time.time() * 1000))
        runReportrequestVars = runReporthttpVerb + runReportepoch + runReportdata + runReportresourcePath
        runReporthmac1 = hmac.new(accessKey.encode(),msg=runReportrequestVars.encode(),digestmod=hashlib.sha256).hexdigest()
        runReportsignature = base64.b64encode(runReporthmac1.encode())
        runReportauth = 'LMv1 ' + accessId + ':' + runReportsignature.decode() + ':' + runReportepoch
        runReportheaders = {'Content-Type':'application/json','Authorization':runReportauth}

        #Make request to run reports and grab URL of generated CSV
        runReportresponse = requests.post(runReporturl, data=runReportdata, headers=runReportheaders)
        runReportdata = json.loads(runReportresponse.content)
        reportUrl = runReportdata["data"]["resulturl"]

        #open a connection to a URL using urllib
        webUrl  = urllib.request.urlopen(reportUrl)

        #read the data from the URL and decode it
        webData = webUrl.read()
        decodedData = webData.decode()
        decodedData.replace("\u200b", "")
        
        #split output on each new line from the report to get our rows. Remove first 5 rows of each report
        rawAlertList = decodedData.split('\n')
        alertList = rawAlertList[5:]
        
        #loop over each line of the alert list and split on commas to get our individual cell values for row
        for item in alertList:
            #below logic will allow us to split on commas while ignoring commas enclosed within quotation marks
            alertArray = [ '"{}"'.format(x) for x in list(csv.reader([item], delimiter=',', quotechar='"'))[0] ]
            if len(alertArray) >= 6:
                #append row to master list
                masterList.append(alertArray)
        logging.info("Cumulative alerts so far on day " + str(reportCounter) + " - " + str(len(masterList)))
        reportCounter +=1

    csvList = []
    for alertEntry in masterList:
        severity = alertEntry[0].strip('"')
        deviceName = alertEntry[1].strip('"')
        datasource = alertEntry[2].strip('"')
        instanceName = alertEntry[3].strip('"')
        datapoint = alertEntry[4].strip('"')
        began = alertEntry[5].strip('"')
        group = alertEntry[6].strip('"')
        
        #some logic here to parse the group value and look for the presence of "1. Clients/" then grab the following 3 characters
        splitGroup = group.split("Clients/")
        previous = next_object = None
        splitGroupLength = len(splitGroup)
        
        #default value for client_code is defined below. If device belongs to a client, it will be adjusted to be the client code
        client_code = "CDI Managed Services"
        for index, obj in enumerate(splitGroup):
            #check split array for presence of '1. '. Since we split on 'Clients/', the next iteration after '1. ' will start with the client code
            if obj.endswith("1. "):
                if index < (splitGroupLength - 1):
                    next_object = splitGroup[index + 1]
                    #pull the client code off of the first 3 characters of this object
                    client_code = next_object[0:3]

        #append values to dictionary object which represents 1 row on the report.
        temp_dict = {"Severity": severity, "Device": deviceName, "Datasource": datasource, "Instance": instanceName, "Datapoint": datapoint, "Began": began, "Client Code": client_code, "Group": group}
        csvList.append(temp_dict)

    totalAlerts = len(csvList)
    logging.info("Total alerts past " + str(daysOfAlerts) + " days - " + str(totalAlerts))

    #Once I get the output all pieced together, I need to delete all the reports generated
    for reportIdToDelete in reportIdList:
        deleteReporthttpVerb ='DELETE'
        deleteReportresourcePath = '/report/reports/' + str(reportIdToDelete)
        deleteReporturl = 'https://'+ lmCompany +'.logicmonitor.com/santaba/rest' + deleteReportresourcePath 
        deleteReportepoch = str(int(time.time() * 1000))
        deleteReportrequestVars = deleteReporthttpVerb + deleteReportepoch + deleteReportresourcePath
        deleteReporthmac1 = hmac.new(accessKey.encode(),msg=deleteReportrequestVars.encode(),digestmod=hashlib.sha256).hexdigest()
        deleteReportsignature = base64.b64encode(deleteReporthmac1.encode())
        deleteReportauth = 'LMv1 ' + accessId + ':' + deleteReportsignature.decode() + ':' + deleteReportepoch
        deleteReportheaders = {'Content-Type':'application/json','Authorization':deleteReportauth}

        deleteReportresponse = requests.delete(deleteReporturl, headers=deleteReportheaders)

    logging.info("Reports successfully deleted")
    returnData = json.dumps({"data":csvList}) 
    return returnData