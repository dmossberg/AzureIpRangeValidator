# Download
Download compiled binaries from [here](https://github.com/dmossberg/AzureIpRangeValidator/blob/master/AzureIpRangeValidator.zip) 

# Usage (for Windows)
```
AzureIpRangeValidator.exe --logfile samplelog.csv --servicetagfile azureservicetags.json
```

# Usage (other OS)
```
dotnet AzureIpRangeValidator.dll --logfile samplelog.csv --servicetagfile azureservicetags.json
```

# Help
```
C:\temp\AzureIpRangeValidator.exe --help

AzureIpRangeValidator 1.0.0
Copyright (C) 2020 AzureIpRangeValidator

  --logfile           Required. Full path to log file to be parsed in CSV format

  --servicetagfile    Required. Full path to Azure Service Tag JSON

  -v, --verbose       (Default: false) Verbose mode for troubleshooting errors

  -t, --tab           (Default: false) Use tab (\t) as delimiter for the CSV file, default is semicolon

  -c, --comma         (Default: false) Use comma (,) as delimiter for the CSV file, default is semicolon

  --help              Display this help screen.

  --version           Display version information.
  ```
