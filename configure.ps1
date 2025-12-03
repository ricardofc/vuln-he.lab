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
    # Buscamos onde está o script actual (que está no CD) e collemos o EXE de aí
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
    # NOTA: O comando Install-ADDSForest forzará un reinicio automático ao rematar.
    Write-Host "[*] Instalando rol AD DS e promovendo a DC..."
    Install-WindowsFeature AD-Domain-Services, RSAT-AD-PowerShell -IncludeManagementTools
    $password = ConvertTo-SecureString "abc123." -AsPlainText -Force
    Install-ADDSForest `
        -DomainName "VULN-HE.LAB" `
        -DomainNetBIOSName "VULN-HE" `
        -InstallDns:$true `
        -SafeModeAdministratorPassword $password `
        -Force
        
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
    # Aseguramos que o Directorio Activo (NTDS/ADWS) estea totalmente operativo antes de lanzar comandos.
    Write-Host "[*] Agardando polos servizos de Active Directory..."
    while ((Get-Service -Name NTDS -ErrorAction SilentlyContinue).Status -ne 'Running') { Start-Sleep -Seconds 5 }
    while ((Get-Service -Name ADWS -ErrorAction SilentlyContinue).Status -ne 'Running') { Start-Sleep -Seconds 5 }
    Import-Module ActiveDirectory
    $ADServer = "$($env:COMPUTERNAME).VULN-HE.LAB"
    $adReady = $false
    $retryCount = 0
    while (-not $adReady -and $retryCount -lt 20) {
        try { Get-ADDomain -Server $ADServer -ErrorAction Stop | Out-Null; $adReady = $true }
        catch { $retryCount++; Start-Sleep -Seconds 10 }
    }
    if (-not $adReady) { Write-Host "[!] ERRO CRÍTICO: AD non respondeu."; shutdown.exe /s /t 60 /f; exit 1 }
    Write-Host "[+] Servizos de AD listos."
    
    # 2. Configuración de usuarios e vulnerabilidades
    Write-Host "[*] Configurando vulnerabilidades do dominio..."
    $domain = (Get-ADDomain -Server $ADServer).DNSRoot
    
    # Política de Contrasinais: Permite claves moi débiles (ex: "iloveyou")
    Write-Host "[*] Relaxando completamente a política de contrasinais..."
    Set-ADDefaultDomainPasswordPolicy -Identity $domain `
        -ComplexityEnabled $false `
        -MinPasswordLength 0 `
        -PasswordHistoryCount 0 `
        -MinPasswordAge ([System.TimeSpan]::FromDays(0)) `
        -Server $ADServer

    gpupdate /force
    Start-Sleep -Seconds 20
    
    # Creación de Unidades Organizativas (OUs) e Usuarios Base
    New-ADOrganizationalUnit -Name "UsuariosLab" -Server $ADServer
    New-ADOrganizationalUnit -Name "ServidoresLab" -Server $ADServer
    
    # Usuario 'Brais': Terá privilexios de Backup (vulnerable a extracción de NTDS.dit)
    $passBrais = ConvertTo-SecureString "iloveyou" -AsPlainText -Force
    New-ADUser -Name "Brais" -SamAccountName "brais.t" -Path "OU=UsuariosLab,DC=VULN-HE,DC=LAB" -AccountPassword $passBrais -Enabled $true -PasswordNeverExpires $true -Server $ADServer
    
    # Usuario 'Maria': Terá privilexios de Impersonate (vulnerable a Potato attacks)
    $passMaria = ConvertTo-SecureString "dragon" -AsPlainText -Force
    New-ADUser -Name "Maria" -SamAccountName "maria.g" -Path "OU=UsuariosLab,DC=VULN-HE,DC=LAB" -AccountPassword $passMaria -Enabled $true -PasswordNeverexpires $true -Server $ADServer
    
    # CONFIGURACIÓN DE ACCESO REMOTO (WinRM e RDP) - MULTIDIOMA
    # =========================================================================
    Write-Host "[*] Configurando accesos remotos para Brais e Maria (multi-idioma)..."
    
    # 1. Habilitar conexións RDP no servidor
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0

    # 2. Función para obter o nome local dun grupo BUILTIN a partir do seu SID
    function Get-LocalGroupNameFromSid {
        param(
            [Parameter(Mandatory=$true)]
            [string]$Sid
        )

        $sidObj    = New-Object System.Security.Principal.SecurityIdentifier($Sid)
        $ntAccount = $sidObj.Translate([System.Security.Principal.NTAccount])
        return $ntAccount.Value.Split('\')[1]   # devolve só o nome do grupo sen o prefijo de equipo
    }

    # 3. SIDs ben coñecidos dos grupos BUILTIN
    # Remote Desktop Users (multi-idioma)
    $sidRDP   = "S-1-5-32-555"
    # Remote Management Users (multi-idioma)
    $sidWinRM = "S-1-5-32-580"

    # Obtención de nomes locais multi-idioma
    $grpRDP   = Get-LocalGroupNameFromSid $sidRDP
    $grpWinRM = Get-LocalGroupNameFromSid $sidWinRM

    Write-Host "[+] Grupo RDP local detectado:   $grpRDP"
    Write-Host "[+] Grupo WinRM local detectado: $grpWinRM"

    # 4. Engadir usuarios aos grupos locais BUILTIN
    # Estes grupos son LOCAIS (SAM), non obxectos de AD, por iso empregamos 'net localgroup'
    Write-Host "[*] Engadindo usuarios aos grupos locais BUILTIN..."
    net localgroup "$grpWinRM" "VULN-HE\brais.t" /add
    net localgroup "$grpRDP"   "VULN-HE\maria.g" /add
    
    # Maria en WinRM
    net localgroup "$grpWinRM" "VULN-HE\maria.g" /add

    # 5. Habilitar WinRM / PSRemoting para usuarios non admin
    Write-Host "[*] Habilitando PSRemoting e autenticación para WinRM..."
    Enable-PSRemoting -Force

    # Asegurar autenticación Negotiate / NTLM / Kerberos (compatibles con ferramentas ofensivas)
    Set-Item -Path WSMan:\localhost\Service\Auth\Kerberos  -Value $true
    Set-Item -Path WSMan:\localhost\Service\Auth\Negotiate -Value $true
    Set-Item -Path WSMan:\localhost\Service\Auth\NTLM      -Value $true

    # Permitir tráfico non cifrado (laboratorio inseguro por deseño)
    Set-Item -Path WSMan:\localhost\Service\AllowUnencrypted -Value $true

    Write-Host "[+] Acceso remoto RDP + WinRM configurado correctamente (multi-idioma)."
    
    # VULNERABILIDADE: AS-REP Roasting
    # Usuario 'NoPreAuthUser': Configurámolo para non requirir pre-autenticación Kerberos.
    $password_asrep = ConvertTo-SecureString "AsrepMePlease123" -AsPlainText -Force
    New-ADUser -Name "NoPreAuthUser" -SamAccountName "nopreauth.user" -Path "OU=UsuariosLab,DC=VULN-HE,DC=LAB" -AccountPassword $password_asrep -Enabled $true -PasswordNeverExpires $true -Server $ADServer
    Write-Host "[*] Configurando 'Don't require Pre-Authentication' para AS-REP Roasting..."
    $userToModify = Get-ADUser -Identity "nopreauth.user" -Properties userAccountControl -Server $ADServer
    $newUac = $userToModify.userAccountControl -bor 0x400000
    Set-ADUser -Identity "nopreauth.user" -Replace @{ userAccountControl = $newUac } -Server $ADServer

    # VULNERABILIDADE: Kerberoasting
    # Usuario 'SQLService': Asignámoslle un SPN, o que permite solicitar o seu TGS e crackear o contrasinal.
    $password_svc = ConvertTo-SecureString "SvcPassw0rdKerb!" -AsPlainText -Force
    New-ADUser -Name "SQLService" -SamAccountName "svc_sql" -Path "OU=UsuariosLab,DC=VULN-HE,DC=LAB" -AccountPassword $password_svc -Enabled $true -PasswordNeverExpires $true -Server $ADServer
    Set-ADUser -Identity "svc_sql" -ServicePrincipalNames @{Add="MSSQLSvc/VULN-DC-01.vuln-he.lab:1433"} -Server $ADServer
    
    # VULNERABILIDADE: Unconstrained Delegation
    # O propio DC confígurase para delegación non restrinxida (perigoso se un Admin se conecta a el).
    $dc = Get-ADDomainController -Server $ADServer
    Get-ADComputer -Identity $dc.Name -Server $ADServer | Set-ADAccountControl -TrustedForDelegation $true
    
    # VULNERABILIDADE: Abuso de ACLs
    # O grupo 'HelpDesk' ten control total sobre o usuario 'Maria'.
    New-ADGroup -Name "HelpDesk" -GroupScope Global -Path "OU=UsuariosLab,DC=VULN-HE,DC=LAB" -Server $ADServer
    $password_helpdesk = ConvertTo-SecureString "HelpDeskP@ss1" -AsPlainText -Force
    New-ADUser -Name "HelpDeskUser" -SamAccountName "helpdesk.user" -Path "OU=UsuariosLab,DC=VULN-HE,DC=LAB" -AccountPassword $password_helpdesk -Enabled $true -PasswordNeverExpires $true -Server $ADServer
    Add-ADGroupMember -Identity "HelpDesk" -Members "helpdesk.user" -Server $ADServer
    
    $aclPath = "AD:\CN=Maria,OU=UsuariosLab,DC=VULN-HE,DC=LAB"
    $acl = Get-Acl $aclPath
    $user = New-Object System.Security.Principal.NTAccount("VULN-HE\HelpDesk")
    $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($user, "GenericAll", "Allow")
    $acl.AddAccessRule($rule)
    Set-Acl -Path $aclPath -AclObject $acl
    
    # -------------------------------------------------------------------------
    # CONFIGURACIÓN AVANZADA DE SEGURIDADE (Privilexios e NTLM Relay)
    # Usamos un ficheiro INF e 'secedit' para aplicar cambios profundos na política local.
    # -------------------------------------------------------------------------
    $braisSID = (Get-ADUser -Identity 'brais.t' -Server $ADServer).SID.Value
    $mariaSID = (Get-ADUser -Identity 'maria.g' -Server $ADServer).SID.Value
    # SID para SeServiceLogonRight
    $svcSqlSID = (Get-ADUser -Identity 'svc_sql' -Server $ADServer).SID.Value
    
    # Definimos o contido da política:
    # 1. [Registry Values]: Forza a desactivación da Firma SMB (RequireSecuritySignature=0) para permitir NTLM Relay.
    # 2. [Privilege Rights]: Asigna SeBackupPrivilege a Brais e SeImpersonatePrivilege a Maria.
    # 3. SeServiceLogonRight para SQL
    $inf = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Registry Values]
; 4 = REG_DWORD, 0 = Valor (Desactivado)
MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters\RequireSecuritySignature=4,0
MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters\EnableSecuritySignature=4,0
[Privilege Rights]
SeBackupPrivilege = *$braisSID
SeImpersonatePrivilege = *$mariaSID
SeServiceLogonRight = *$svcSqlSID
"@
    
    # Aplicamos a política coa ferramenta nativa secedit
    $infPath = "C:\temp_secpolicy.inf"
    $inf | Out-File $infPath -Encoding unicode
    Write-Host "[*] Aplicando política de seguridade local (Privilexios e SMB Signing)..."
    secedit /configure /db c:\windows\security\local.sdb /cfg $infPath /areas USER_RIGHTS SECURITYPOLICY
    Remove-Item $infPath -Force
    
    gpupdate /force
    
    # Desactivar Firewall e Activar WDigest (Credenciais en texto plano en LSASS)
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
    New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value 1 -PropertyType DWORD -Force
    
    # Activar LLMNR/Multicast (Para ataques de envelenamento como Responder)
    if (-not (Test-Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient")) { New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Force }
    New-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 1 -PropertyType DWORD -Force
    
    # VULNERABILIDADE: SMBv1
    # Instalamos e forzamos a activación do protocolo obsoleto SMBv1.
    Write-Host "[*] VULNERABILIDADE: Instalando e activando SMBv1..."
    Install-WindowsFeature FS-SMB1
    Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force

    # Aseguramento final de desactivación de firma SMB no rexistro (Redundancia para garantir NTLM Relay)
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "requiresecuritysignature" -Value 0 -PropertyType DWORD -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "enablesecuritysignature" -Value 0 -PropertyType DWORD -Force

    # =========================================================================
    # INSTALACIÓN E CONFIGURACIÓN OFFLINE DE SQL SERVER
    # =========================================================================
    $sqlInstaller = "C:\SQLEXPR_x64_ENU.exe"
    if (Test-Path $sqlInstaller) {
        Write-Host "[*] [SQL] Instalando SQL Server 2019 Express (Offline)..."
        # Argumentos para instalación silenciosa
        $argsSQL = "/q /ACTION=Install /FEATURES=SQL /INSTANCENAME=SQLEXPRESS /SQLSVCACCOUNT='NT AUTHORITY\System' /SQLSYSADMINACCOUNTS='BUILTIN\ADMINISTRATORS' /TCPENABLED=1 /NPENABLED=1 /IACCEPTSQLSERVERLICENSETERMS"
        Start-Process -FilePath $sqlInstaller -ArgumentList $argsSQL -Wait
        
        Write-Host "[*] [SQL] Configurando servizo para correr como VULN-HE\svc_sql..."
        $serviceName = "MSSQL`$SQLEXPRESS"
        $serviceUser = "VULN-HE\svc_sql"
        $servicePass = "SvcPassw0rdKerb!"
        
        try {
            Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
            $scArgs = "config $serviceName obj= `"$serviceUser`" password= `"$servicePass`""
            Start-Process -FilePath "sc.exe" -ArgumentList $scArgs -Wait -NoNewWindow
            Start-Service -Name $serviceName
            Write-Host "[+] [SQL] Servizo configurado."
        } catch {
            Write-Host "[!] [SQL] Erro configurando o servizo: $_"
        }
    } else {
        Write-Host "[!] [SQL] Instalador non atopado en C:\SQLEXPR_x64_ENU.exe"
    }

    # =========================================================================
    # VULNERABILIDADE: Tarefa programada do Administrador para Envelenamento LLMNR
    # =========================================================================
    # Creamos unha tarefa que se executa coas credenciais do Administrador.
    # Intenta acceder a un recurso compartido que non existe (\\SRV-BACKUP-01\Data).
    # Isto xerará tráfico LLMNR/NBT-NS buscando ese host, permitindo capturar o hash NTLMv2 con Responder.
    Write-Host "[*] VULNERABILIDADE: Creando tarefa programada 'DailyBackupCheck' para captura de hash de Admin..."
    
    $taskName = "DailyBackupCheck"
    $adminUser = "VULN-HE\Administrador"
    $adminPass = "abc123." # Contrasinal definido no Autounattend.xml e script
    
    # Acción: Intentar listar un cartafol nun servidor inexistente
    $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c dir \\SRV-BACKUP-01\Data"
    
    # Trigger: Executar unha vez agora, e repetir cada 1 minuto indefinidamente
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 1)
    
    # Configuración: Permitir inicio se non está conectado á corrente, etc.
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
    
    # Rexistro da tarefa como Administrador
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -User $adminUser -Password $adminPass -Force
    
    Write-Host "[+] Tarefa de tráfico malicioso creada."

    # Apagado final para rematar a creación da imaxe
    Write-Host "[+] Configuración do laboratorio vulnerable completada. Apagando..."
    Stop-Transcript
    shutdown.exe /s /t 10 /f
}
