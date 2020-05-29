# DataCollection

# Scope

Running this PS1 file will read registry key settings and their current values to ensure they meet the Intune compliance policies set by the organization.
It will not change any registry values, simply display those values that do not match the required settings.
Download package

Navigate to https://github.com/AdrianKruss/DataCollection and download Get-RDWVDIntuneSettings.ps1

# Run

1.	From your Intune registered Windows 10 machine open PowerShell as administrator.

2.	Then run:

      ``` Set-ExecutionPolicy RemoteSigned ```


3.	After completion run:
```
          Install-Module PSWriteHTML -Force

```
4.	Then launch Get-RDWVDIntuneSettings.ps1

5.	Once the script completed it will give you the results in HTML format:
 
    a.	If all values are setup correctly it will show "Device settings match required Intune compliance settings"
 
    b.	If any value is not setup correctly it will display the errors 
    
    

    c.	The output file will also be saved on the same path where the PS1 is being run from as Intune.html in case you need to share it.
