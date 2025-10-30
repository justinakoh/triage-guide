# SOC Alert Cheat Sheet - Microsoft
## Don't know where to start?
**Where to run queries?**

Microsoft uses Kusto Query Language (KQL) to query for datasets (such as logs). There are two main regions where you can run these queries:
* Microsoft Defender - 
* Micrsoft Sentinel - 

These two places will have different subset of logs that you can pull from, and this means that there will be different things you can find within:
* Microsoft Entra - identity related information
* Microsoft Sentinel - 
* Microsoft Defender - this is better for things to do with endpoints and for real-time actions 

**Find all tables where a string exists**

```
search "STRING"
| summarize $Table
```
Alternatively, you could also just run `serach "STRING"` to get back all the logs where that string is seen within. 

## Connection to a custom network indicator

This is a Microsoft alert that is customised by the client. In Defender, you have the ability to add URLs, IP addresses, domains, and even apps to a custom list. Access to these things can be blocked and create an alert at the same time.

Where to look:
* List of URL/domains that are blocked: https://security.microsoft.com/securitysettings/endpoints/custom_ti_indicators
* List of sanctioned / blocked applications: https://security.microsoft.com/cloudapps/app-catalog


**Block download based on real-time content inspection involving one user**

This is an alert which falls under Microsoft's "Threat Protection", and under Defender's Conditional Access session policies. This is a customised alert which the Administrator is able to set specific restrictions on what alerts are triggered based on what the content of what the user has been downloaded. 

Where to look:
* XXX

How to configure this alert: 
* Log into Defender
* Navigate to "Cloud Apps" > "Policies" > "Policy Management" > "Conditional Access" tab
* Select "Create policy" > "Session policy"
* Fill out the form. This is where you are able to set controls around file download. 


## Attempt to bypass conditional access policy

When logging into Microsoft, one of the values that needs to be fulfilled is the "ConditionAccessStatus" column. This can equal one of the following:
* ConditionalAccessStatus == 0 Success
* ConditionalAccessStatus == 1 Failure
* ConditionalAccessStatus == 2 Not applied
* ConditionalAccessStatus == 3 Unknown

Microsoft does periodic searches for when ConditionalAccessStatus == 1 and will create an alert if this occurs. The reason why this alert has been put in is because there are ways to bypass conditional access policies if the policies are not correctly configured. One way to do this is through PowerShell. 

Helpful Query / Notes:
```
1. Pull the user's Signin logs. You want to look for anomalies in their sign in behaviour. Check for:
* Devices used - is this the normal one / is it managed?
* Location and IP address
* Time of login - is this a normal time for this user?
* History of sign in leading up - are there mulitple failed logins from strange logins?

Query:
SigninLogs
| where UserPrincipalName contains "NAME"
| project TimeGenerated, ConditionalAccessStatus, IPAddress, Location, DeviceDetail, UserPrincipalName, MfaDetail, ConditionalAccessPolicies
``
```

Helpful References:
* [Common CA Misconfiguration and Bypasses Azure](https://www.google.com/search?q=attempt+to+bypass+conidtional+access+poicy&rlz=1C1GCEA_enNZ1173NZ1173&oq=attempt+to+bypass+conidtional+access+poicy+&gs_lcrp=EgZjaHJvbWUyBggAEEUYOdIBCDU3NjNqMGoxqAIAsAIA&sourceid=chrome&ie=UTF-8&sei=Q1j1aOLXIavLseMPutiDkAw)

Other Notes:
* Guests to tenancies will appear in the SignInLogs for the tenancy.
* If you are sent a link to a document (for example), you click on it, and you attempt to sign in to view the document, you will also appear in that tenancy's sign in logs, even if you are not a guest or part of their tenancy.

## SharePointFileOperation via previously unseen IPs
Identifies anomalies using user behavior by setting a threshold for significant changes in file upload/download activities from new IP addresses. It establishes a baseline of typical behavior, compares it to recent activity, and flags deviations exceeding a default threshold of 25.

## NRT User added to Microsoft Entra ID Privileged Groups involving multiple users

This triggers whenever any user is added to any of the Privileged groups. This also applies for PIM.

## Local admin account used to logon into the computer

Pretty self explanatory, user has logged into computer using Local Admin account. 

What to look for:
* Check that there are no anomalies within log in history. Check that the host, IP, location are all typical for the user 
**Insider Risk_Risky User Access By Application involving one user**

## A possible vulnerability to SQL Injection involving one user 

This occurs when an application generates a faulty SQL statement in the database which indicates a possible vulnerability to SQL injection attacks. 

