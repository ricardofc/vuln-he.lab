# configure.ps1
# Script mestre único para crear o laboratorio AD vulnerable.
# Xestiónase a si mesmo a través dunha clave de rexistro RunOnce para sobrevivir ao reinicio.

param(
    [ValidateSet("Install", "PostConfig")]
    [string]$Phase = "Install"
)

$logInstall        = "C:\packer-log-install.txt"
$logPostConfig     = "C:\packer-log-postconfig.txt"
$localScriptPath   = "C:\configure.ps1"

# Función para borrar chaves de reinicio pendente (Necesario para que SQL non falle)
function Clear-PendingReboot {
    Write-Host "[*] Limpando rexistro de reinicios pendentes..."
    $keys = @(
        "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"
    )
    foreach ($key in $keys) {
        if ($key -match "PendingFileRenameOperations") {
             Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "PendingFileRenameOperations" -ErrorAction SilentlyContinue
        } else {
             if (Test-Path $key) { Remove-Item -Path $key -Force -Recurse -ErrorAction SilentlyContinue }
        }
    }
}

# ============================================================
# FASE 1: Preparación do sistema e promoción a Controlador de Dominio
# ============================================================
if ($Phase -eq "Install") {
    Start-Transcript -Path $logInstall -Force
    Write-Host "[*] FASE 1: Iniciando configuración..."

    # 1. Persistencia do script
    # Copiamos o script actual ao disco C: para que estea dispoñible despois de que Windows reinicie.
    Write-Host "[*] Copiando o script a $localScriptPath..."
    Copy-Item -Path $MyInvocation.MyCommand.Path -Destination $localScriptPath -Force
    
    # Copiar tamén o instalador SQL do CD ao disco C: para usalo na Fase 2
    $sourceDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    $sqlInstallerSource = "$sourceDir\SQLEXPR_x64_ENU.exe"
    $sqlInstallerDest   = "C:\SQLEXPR_x64_ENU.exe"
    
    if (Test-Path $sqlInstallerSource) {
        Write-Host "[*] Copiando instalador SQL Server ao disco local..."
        Copy-Item -Path $sqlInstallerSource -Destination $sqlInstallerDest -Force
    } else {
        Write-Host "[!] AVISO: Non se atopou o instalador SQL no medio de orixe ($sqlInstallerSource)."
    }

    # 2. Configuración de execución automática (RunOnce)
    # Creamos unha entrada no rexistro para que a FASE 2 arranque automaticamente tras o seguinte inicio de sesión.
    Write-Host "[*] Configurando a clave de rexistro RunOnce para a Fase 2..."
    $command = "powershell.exe -ExecutionPolicy Bypass -File $localScriptPath -Phase PostConfig"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" -Name "PostADConfig" -Value $command

    # 3. Configuración de rede e sistema base
    # Establecemos unha IP estática necesaria para un DC e desactivamos Defender para facilitar as probas.
    Write-Host "[*] Configurando rede estática e sistema..."
    Start-Sleep -Seconds 15
    $adapter = Get-NetAdapter | Sort-Object ifIndex | Select-Object -First 1
    Set-NetIPInterface -InterfaceAlias $adapter.Name -Dhcp Disabled -ErrorAction SilentlyContinue
    Remove-NetIPAddress -InterfaceAlias $adapter.Name -AddressFamily IPv4 -Confirm:$false -ErrorAction SilentlyContinue
    New-NetIPAddress -InterfaceAlias $adapter.Name -IPAddress 192.168.56.100 -PrefixLength 24
    Set-DnsClientServerAddress -InterfaceAlias $adapter.Name -ServerAddresses 127.0.0.1
    Set-MpPreference -DisableRealtimeMonitoring $true
    Set-Service WinDefend -StartupType Disabled -ErrorAction SilentlyContinue
    
    # 4. Promoción a Controlador de Dominio
    # Instalamos os binarios do AD e creamos o bosque "VULN-HE.LAB".
    Write-Host "[*] Instalando rol AD DS e promovendo a DC..."
    Install-WindowsFeature AD-Domain-Services, RSAT-AD-PowerShell -IncludeManagementTools
    $password = ConvertTo-SecureString "abc123." -AsPlainText -Force
    
    # NOTA: -Confirm:$false evita bloqueos interactivos
    Install-ADDSForest `
        -DomainName "VULN-HE.LAB" `
        -DomainNetBIOSName "VULN-HE" `
        -InstallDns:$true `
        -SafeModeAdministratorPassword $password `
        -Force `
        -Confirm:$false
        
    Write-Host "[*] Fase 1 completada. O sistema reiniciarase agora."
    Stop-Transcript
    exit
}

# ============================================================
# FASE 2: Configuración das vulnerabilidades do laboratorio
# ============================================================
if ($Phase -eq "PostConfig") {
    Start-Transcript -Path $logPostConfig -Force
    Write-Host "[*] FASE 2: Iniciando configuración post-reinicio..."

    # 1. Espera activa polos servizos
    Write-Host "[*] Agardando polos servizos de Active Directory..."
    while ((Get-Service -Name NTDS -ErrorAction SilentlyContinue).Status -ne 'Running') { Start-Sleep -Seconds 5 }
    while ((Get-Service -Name ADWS -ErrorAction SilentlyContinue).Status -ne 'Running') { Start-Sleep -Seconds 5 }
    
    $retryCount = 0
    $adReady = $false
    while (-not $adReady) {
        try {
            Import-Module ActiveDirectory -ErrorAction SilentlyContinue
            $domainInfo = Get-ADDomain -ErrorAction Stop
            $adReady = $true
            Write-Host "[+] Conexión con AD exitosa: $($domainInfo.DNSRoot)"
        }
        catch {
            $retryCount++
            Write-Host "[*] AD aínda non responde ($retryCount)..."
            Start-Sleep -Seconds 5
        }
    }
    $domainRoot = $domainInfo.DNSRoot
    $ADServer = "localhost"
    $domainDN = $domainInfo.DistinguishedName

    # --------------------------------------------------------
    # FIX CRÍTICO SMB SIGNING (Directamente na GPO do SYSVOL)
    # --------------------------------------------------------
    # Isto é necesario porque nos DCs a "Default Domain Controller Policy" forzas a firma.
    # Modificamos o ficheiro INF dentro do SYSVOL para que a GPO distribúa "Disabled".
    Write-Host "[*] FIX: Modificando a GPO en SYSVOL para desactivar SMB Signing..."
    
    # GUID da Default Domain Controller Policy
    $gpoPath = "$($env:SystemRoot)\SYSVOL\sysvol\$domainRoot\Policies\{6AC1786C-016F-11D2-945F-00C04FB984F9}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
    
    if (Test-Path $gpoPath) {
        $content = Get-Content $gpoPath -Raw
        # Reemplazar 4,1 (Enabled) por 4,0 (Disabled)
        $newContent = $content -replace "RequireSecuritySignature\s*=\s*4,1", "RequireSecuritySignature=4,0"
        $newContent = $newContent -replace "EnableSecuritySignature\s*=\s*4,1", "EnableSecuritySignature=4,0"
        
        # Se non existen as liñas, engadímolas
        if ($newContent -notmatch "RequireSecuritySignature") {
             $newContent = $newContent -replace "\[Registry Values\]", "[Registry Values]`r`nMACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters\RequireSecuritySignature=4,0`r`nMACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters\EnableSecuritySignature=4,0"
        }
        Set-Content -Path $gpoPath -Value $newContent -Force
        Write-Host "[+] GPO modificada en disco. Signing manterase desactivado."
    }

    # --------------------------------------------------------
    # VULNERABILIDADE: SMBv1
    # --------------------------------------------------------
    Write-Host "[*] VULNERABILIDADE: Instalando e activando SMBv1..."
    Install-WindowsFeature FS-SMB1 -ErrorAction SilentlyContinue
    
    # Usamos try/catch para evitar erros vermellos se o servizo aínda non existe
    try {
        Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force -ErrorAction Stop
    } catch {
        Write-Host "[!] Aviso: O servizo SMB aínda non existe (normal). Activando vía Rexistro."
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Value 1 -PropertyType DWORD -Force
    }
    
    # 2. Configuración de usuarios e vulnerabilidades
    Write-Host "[*] Configurando vulnerabilidades do dominio..."
    
    # Política de Contrasinais: Permite claves moi débiles (ex: "iloveyou")
    Write-Host "[*] Relaxando completamente a política de contrasinais..."
    Set-ADDefaultDomainPasswordPolicy -Identity $domainRoot `
        -ComplexityEnabled $false `
        -MinPasswordLength 0 `
        -PasswordHistoryCount 0 `
        -MinPasswordAge ([System.TimeSpan]::FromDays(0)) `
        -Server $ADServer
    
    # Creación de Unidades Organizativas (OUs) e Usuarios Base
    New-ADOrganizationalUnit -Name "UsuariosLab" -Server $ADServer
    
    # Usuario 'Brais': Terá privilexios de Backup (vulnerable a extracción de NTDS.dit)
    $passBrais = ConvertTo-SecureString "iloveyou" -AsPlainText -Force
    New-ADUser -Name "Brais" -SamAccountName "brais.t" -Path "OU=UsuariosLab,$domainDN" -AccountPassword $passBrais -Enabled $true -PasswordNeverExpires $true -Server $ADServer
    
    # Usuario 'Maria': Terá privilexios de Impersonate (vulnerable a Potato attacks)
    $passMaria = ConvertTo-SecureString "dragon" -AsPlainText -Force
    New-ADUser -Name "Maria" -SamAccountName "maria.g" -Path "OU=UsuariosLab,$domainDN" -AccountPassword $passMaria -Enabled $true -PasswordNeverexpires $true -Server $ADServer
    
    # CONFIGURACIÓN DE ACCESO REMOTO (WinRM e RDP) - MULTIDIOMA
    # =========================================================================
    Write-Host "[*] Configurando accesos remotos para Brais e Maria (multi-idioma)..."
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0

    function Get-LocalGroupNameFromSid {
        param([string]$Sid)
        $sidObj = New-Object System.Security.Principal.SecurityIdentifier($Sid)
        return $sidObj.Translate([System.Security.Principal.NTAccount]).Value.Split('\')[1]
    }
    
    $grpRDP   = Get-LocalGroupNameFromSid "S-1-5-32-555"
    $grpWinRM = Get-LocalGroupNameFromSid "S-1-5-32-580"
    Write-Host "[+] Grupos locais detectados: RDP=$grpRDP, WinRM=$grpWinRM"

    Write-Host "[*] Engadindo usuarios aos grupos locais BUILTIN..."
    net localgroup "$grpWinRM" "VULN-HE\brais.t" /add
    net localgroup "$grpWinRM" "VULN-HE\maria.g" /add
    net localgroup "$grpRDP"   "VULN-HE\maria.g" /add

    # Habilitar WinRM / PSRemoting de forma robusta
    Write-Host "[*] Habilitando PSRemoting e autenticación para WinRM..."
    Enable-PSRemoting -Force
    
    Start-Sleep -Seconds 5
    if (Test-Path "WSMan:\localhost\Service\Auth") {
        try {
            # Asegurar autenticacións compatibles con ferramentas ofensivas
            Set-Item -Path WSMan:\localhost\Service\Auth\Kerberos  -Value $true -Force -ErrorAction Stop
            Set-Item -Path WSMan:\localhost\Service\Auth\Negotiate -Value $true -Force -ErrorAction Stop
            Set-Item -Path WSMan:\localhost\Service\Auth\NTLM      -Value $true -Force -ErrorAction Stop
            Set-Item -Path WSMan:\localhost\Service\AllowUnencrypted -Value $true -Force -ErrorAction Stop
        } catch {
             Write-Host "[!] Aviso WinRM: Configuración diferida ata o reinicio."
        }
    }
    Write-Host "[+] Acceso remoto RDP + WinRM configurado correctamente."

    # VULNERABILIDADE: AS-REP Roasting
    $password_asrep = ConvertTo-SecureString "AsrepMePlease123" -AsPlainText -Force
    New-ADUser -Name "NoPreAuthUser" -SamAccountName "nopreauth.user" -Path "OU=UsuariosLab,$domainDN" -AccountPassword $password_asrep -Enabled $true -PasswordNeverExpires $true -Server $ADServer
    Write-Host "[*] Configurando 'Don't require Pre-Authentication' para AS-REP Roasting..."
    $userToModify = Get-ADUser -Identity "nopreauth.user" -Properties userAccountControl -Server $ADServer
    Set-ADUser -Identity "nopreauth.user" -Replace @{ userAccountControl = ($userToModify.userAccountControl -bor 0x400000) } -Server $ADServer

    # VULNERABILIDADE: Kerberoasting
    $password_svc = ConvertTo-SecureString "SvcPassw0rdKerb!" -AsPlainText -Force
    New-ADUser -Name "SQLService" -SamAccountName "svc_sql" -Path "OU=UsuariosLab,$domainDN" -AccountPassword $password_svc -Enabled $true -PasswordNeverExpires $true -Server $ADServer
    Set-ADUser -Identity "svc_sql" -ServicePrincipalNames @{Add="MSSQLSvc/VULN-DC-01.vuln-he.lab:1433"} -Server $ADServer

    # VULNERABILIDADE: Unconstrained Delegation
    $dc = Get-ADDomainController -Server $ADServer
    Get-ADComputer -Identity $dc.Name -Server $ADServer | Set-ADAccountControl -TrustedForDelegation $true

    # VULNERABILIDADE: Abuso de ACLs
    # CORRECCIÓN: -GroupScope Global engadido para evitar bloqueo
    New-ADGroup -Name "HelpDesk" -GroupScope Global -Path "OU=UsuariosLab,$domainDN" -Server $ADServer
    $password_helpdesk = ConvertTo-SecureString "HelpDeskP@ss1" -AsPlainText -Force
    New-ADUser -Name "HelpDeskUser" -SamAccountName "helpdesk.user" -Path "OU=UsuariosLab,$domainDN" -AccountPassword $password_helpdesk -Enabled $true -PasswordNeverExpires $true -Server $ADServer
    Add-ADGroupMember -Identity "HelpDesk" -Members "helpdesk.user" -Server $ADServer
    
    $aclPath = "AD:\CN=Maria,OU=UsuariosLab,$domainDN"
    if (Test-Path $aclPath) {
        $acl = Get-Acl $aclPath
        $user = New-Object System.Security.Principal.NTAccount("VULN-HE\HelpDesk")
        $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($user, "GenericAll", "Allow")
        $acl.AddAccessRule($rule)
        Set-Acl -Path $aclPath -AclObject $acl
    }

    # -------------------------------------------------------------------------
    # CONFIGURACIÓN AVANZADA DE SEGURIDADE (Privilexios e NTLM Relay)
    # -------------------------------------------------------------------------
    $braisSID  = (Get-ADUser -Identity 'brais.t' -Server $ADServer).SID.Value
    $mariaSID  = (Get-ADUser -Identity 'maria.g' -Server $ADServer).SID.Value
    # SeServiceLogonRight é vital para que SQL arranque
    $svcSqlSID = (Get-ADUser -Identity 'svc_sql' -Server $ADServer).SID.Value
    
    $inf = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Privilege Rights]
SeBackupPrivilege = *$braisSID
SeImpersonatePrivilege = *$mariaSID
SeServiceLogonRight = *$svcSqlSID
"@
    $infPath = "C:\temp_secpolicy.inf"
    $inf | Out-File $infPath -Encoding unicode
    Write-Host "[*] Aplicando política de seguridade local (Privilexios)..."
    secedit /configure /db c:\windows\security\local.sdb /cfg $infPath /areas USER_RIGHTS
    Remove-Item $infPath -Force
    
    # Desactivar Firewall e Activar WDigest
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
    New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value 1 -PropertyType DWORD -Force
    
    # Activar LLMNR/Multicast
    if (-not (Test-Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient")) { New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Force }
    New-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 1 -PropertyType DWORD -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "requiresecuritysignature" -Value 0 -PropertyType DWORD -Force

    # =========================================================================
    # INSTALACIÓN SQL SERVER 2019 EXPRESS (Versión Robusta)
    # =========================================================================
    $sqlInstaller = "C:\SQLEXPR_x64_ENU.exe"
    $sqlExtractDir = "C:\SQLTemp"
    
    if (Test-Path $sqlInstaller) {
        Write-Host "[*] [SQL] Instalando SQL Server 2019 Express (Offline)..."
        Clear-PendingReboot
        
        Write-Host "[*] [SQL] Extraendo ficheiros..."
        Start-Process -FilePath $sqlInstaller -ArgumentList "/x:$sqlExtractDir /q" -Wait
        
        $setupExe = "$sqlExtractDir\SETUP.EXE"
        if (Test-Path $setupExe) {
            Write-Host "[*] [SQL] Configurando servizo para correr como VULN-HE\svc_sql..."
            
            # Argumentos unidos para evitar erros de parsing
            $sqlArgs = @(
                "/Q",
                "/ACTION=Install",
                "/FEATURES=SQL",
                "/INSTANCENAME=SQLEXPRESS",
                "/SQLSVCACCOUNT=`"VULN-HE\svc_sql`"",
                "/SQLSVCPASSWORD=`"SvcPassw0rdKerb!`"",
                "/SQLSYSADMINACCOUNTS=`"VULN-HE\Administrador`" `"BUILTIN\ADMINISTRATORS`"",
                "/TCPENABLED=1",
                "/NPENABLED=0",
                "/IACCEPTSQLSERVERLICENSETERMS",
                "/SkipRules=RebootRequiredCheck"
            )
            Start-Process -FilePath $setupExe -ArgumentList ($sqlArgs -join " ") -Wait

            $serviceName = "MSSQL`$SQLEXPRESS"
            if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
                # Resiliencia: Arranque diferido
                sc.exe config $serviceName start= delayed-auto
                sc.exe config $serviceName depend= Tcpip/Netlogon
                sc.exe failure $serviceName reset= 86400 actions= restart/5000/restart/5000/restart/5000
                Start-Service -Name $serviceName -ErrorAction SilentlyContinue
                
                # Configurar porto 1433
                $instMap = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL" -ErrorAction SilentlyContinue
                $instId = $instMap.SQLEXPRESS
                if ($instId) {
                    $tcpBase = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$instId\MSSQLServer\SuperSocketNetLib\Tcp\IPAll"
                    Set-ItemProperty -Path $tcpBase -Name TcpPort -Value "1433" -Force
                    Set-ItemProperty -Path $tcpBase -Name TcpDynamicPorts -Value "" -Force
                    Write-Host "[+] [SQL] Servizo configurado no porto 1433."
                }
            }
        }
        if (Test-Path $sqlExtractDir) { Remove-Item $sqlExtractDir -Recurse -Force -ErrorAction SilentlyContinue }
    }

    # =========================================================================
    # VULNERABILIDADE: Tarefa programada do Administrador
    # =========================================================================
    Write-Host "[*] VULNERABILIDADE: Creando tarefa programada 'DailyBackupCheck' para captura de hash de Admin..."
    
    $taskName = "DailyBackupCheck"
    $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c dir \\SRV-BACKUP-01\Data"
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 1)
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -User "VULN-HE\Administrador" -Password "abc123." -Force
    
    Write-Host "[+] Tarefa de tráfico malicioso creada."
    Write-Host "[+] LABORATORIO COMPLETADO CORRECTAMENTE. APAGANDO."
    Stop-Transcript
    Start-Sleep -Seconds 2
    
    # Reinicio final para aplicar GPO e privilexios
    shutdown.exe /s /t 0 /f
}
