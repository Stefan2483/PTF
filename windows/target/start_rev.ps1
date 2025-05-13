$username = 'nagoya-industries.com\svc_mssql'
$password = 'Service1'
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential ($username, $securePassword)
Start-Process -Credential $credential -FilePath "C:\Temp\rev.exe"
