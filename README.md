# Function to push last 7 days of alerts to Azure Blob Storage

The function named "PushAlertsToBlobEnv" is used to grab the past 7 days of alerts from LogicMonitor and then push them to Azure Blob Storage to overwrite the previous data

- This runs on a timer trigger at 9AM everyday and refreshes the data in Azure Blob. Then Power BI pulls data from the blob at 930AM everyday to refresh the report

This will get the alert data for multiple LM portals and add them together. The credentials are stored as an environment variable which is a list of JSON objects. Each JSON object represents the information for 1 LM portal

- The JSON object for an LM portal's info has the below values

  - {"lmCompany":"haservices","accessId":"<insert accessID>","accessKey":"<insert access Key>"}

- Grabbing the past 7 days of alerts
  - To grab the past 7 days of alerts, we create 7 reports in LM, one for each day of the week going back 7 days. Then the contents of those reports are read and added to a master list.
  - The reports are then deleted and the list is converted to JSON and pushed to Azure Blob. The previous data is overwritten

## Adding a new LM portal into the mix

If we want to add a new LM portal into this problem management report, then all we need to do is edit the environment variable defined in the function app's application settings

- This environment variable is named "LMPortalInfo" and is a list of JSON objects. Each JSON object represents 1 LM portal
  - To add a new LM portal, edit the environment variable under the function app and add a new JSON object to the list with the portal name, and API creds of a user with access to view resources/websites, and create/delete reports.

## Limitation in LogicMonitor API's Alerts resource

We are using the Reports resource from the LM API to pull alerts because the filtering based on the alert start time (startEpoch) does not work the way I need it to.

- Only a certain amount of alerts can be pulled via API call (even with offset). So in order to get this to work accurately with the Alerts resource of the API, we would need to use multiple API calls
- We would need to filter on the startEpoch field to get the alerts which triggered BETWEEN 2 times. I can get the startEpoch filter to work for alerts triggered AFTER a certain date, but not BETWEEN
- If we can figure out how to accurately grab alerts from the LM Alerts resource that are between 2 start times, then we can use that to run multiple API calls and get this data in a cleaner way. Until then, we need to use the Reports resource
  - Reports in LogicMonitor have a maximum row size of 30,000. This is why we need to create/delete multiple reports
