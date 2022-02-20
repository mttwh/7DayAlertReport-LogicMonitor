# Function to push last 7 days of alerts to Azure Blob Storage

The function named "PushAlertsToBlobEnv" is used to grab the past 7 days of alerts from LogicMonitor and then push them to Azure Blob Storage to overwrite the previous data

- This runs on a timer trigger at 9AM everyday and refreshes the data in Azure Blob. Then Power BI pulls data from the blob at 930AM everyday to refresh the report

The credentials and LM portal name (used to query the API) are stored in Azure in the Function App application settings as environment variables, where they can be used in the script.

- Grabbing the past 7 days of alerts
  - To grab the past 7 days of alerts, we create 7 reports in LM, one for each day of the week going back 7 days. Then the contents of those reports are read and added to a master list.
  - The reports are then deleted and the list is converted to JSON and pushed to Azure Blob. The previous data is overwritten

# TODO - HTML trigger functions (API calls)

I still need to document the other 3 functions which are part of this function app. They are HTML triggers, which behave as API calls and return a JSON object with LM alerts.

## Limitation in LogicMonitor API's Alerts resource

We are using the Reports resource from the LM API to pull alerts because the filtering based on the alert start time (startEpoch) does not work the way I need it to.

- Only a certain amount of alerts can be pulled via API call (even with offset). So in order to get this to work accurately with the Alerts resource of the API, we would need to use multiple API calls
- We would need to filter on the startEpoch field to get the alerts which triggered BETWEEN 2 times. I can get the startEpoch filter to work for alerts triggered AFTER a certain date, but not BETWEEN
- If we can figure out how to accurately grab alerts from the LM Alerts resource that are between 2 start times, then we can use that to run multiple API calls and get this data in a cleaner way. Until then, we need to use the Reports resource
  - Reports in LogicMonitor have a maximum row size of 30,000. This is why we need to create/delete multiple reports
