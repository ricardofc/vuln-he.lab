# Laboratorio Vulnerable de Active Directory (VULN-HE.LAB) con Packer

Este proxecto automatiza con **Packer** e **PowerShell** a creación dun **Controlador de Dominio Windows Server 2019** intencionadamente vulnerable. O obxectivo é dispoñer dun contorno **didáctico e realista** para practicar técnicas de **Red Team / Pentesting Active Directory**, cubrindo todo o ciclo do ataque, incluíndo **persistencia avanzada en Kerberos**.

**Idioma do Sistema:** Español (es-ES)  

## ⚠️ Aviso Legal e de Seguridade⚠️

**NON EXPOÑAS ESTA MÁQUINA A INTERNET.**  
Este sistema ten o firewall desactivado, antivirus desactivado, protocolos inseguros habilitados e contrasinais débiles. Úsaa unicamente nunha rede illada (Host-Only / NAT Network illada).  
      
O autor do presente documento declina calquera responsabilidade asociada ao uso incorrecto e/ou malicioso que puidese realizarse coa información exposta no mesmo. Por tanto, non se fai responsable en ningún caso, nin pode ser considerado legalmente responsable en ningún caso, das consecuencias que poidan derivarse da información contida nel ou que esté enlazada dende ou hacia el, incluíndo os posibles erros e información incorrecta existentes, información difamatoria, así como das consecuencias que se poidan derivar sobre a súa aplicación en sistemas de información reais e/ou virtuais. Este documento foi xerado para uso didáctico e debe ser empregado en contornas privadas e virtuais controladas co permiso correspondente do administrador desas contornas.

## Credenciais e Acceso

*   **Dominio:** `VULN-HE.LAB` (NetBIOS: `VULN-HE`)
*   **DC IP:** `192.168.56.100` (Estática)  
*   **Credenciais de Dominio:**

| Usuario | Contrasinal | Rol / Vulnerabilidade Clave | Acceso Viable | Utilidade |
| :--- | :--- | :--- | :---: | :--- |
| **Administrador** | `abc123.` | Domain Admin (LLMNR Poisoning) | ✅ | **Game Over** - Control total |
| **brais.t** | `iloveyou` | Backup Operator (SeBackupPrivilege → DA) | ✅ | **Escalada crítica** - Dump NTDS |
| **maria.g** | `dragon` | Potato Attack (SeImpersonatePrivilege → SYSTEM) | ✅ | **Escalada crítica** - SYSTEM vía Potato |
| **nopreauth.user**| `AsrepMePlease123` | AS-REP Roasting (Sen pre-autenticación) | ⚠️ | **Demostración** - Hash non crackeable facilmente |
| **svc_sql** | `SvcPassw0rdKerb!` | Kerberoasting (SPN MSSQL) + **Silver Ticket** | ⚠️ | **Persistencia crítica** - Silver Ticket (10 anos) |
| **helpdesk.user** | `HelpDeskP@ss1` | Abuso de ACLs sobre `maria.g` (vía rpcclient) | ✅ | **Movemento lateral** - GenericAll sobre maria.g |
| **krbtgt** | N/A | Conta de servizo KDC | N/A | **Persistencia MÁXIMA** - Golden Ticket (10 anos) |

**Lenda:**  
- ✅ Acceso directo viable (password spraying ou LLMNR)  
- ⚠️ Acceso indirecto (require compromiso previo para obter hash/contrasinal)  
- N/A Non aplicable (conta de sistema, non de acceso directo)

## Vulnerabilidades Implementadas

1.  **Rede e Protocolos:**
    *   **LLMNR/NBT-NS Poisoning:** Tráfico xerado automaticamente por unha tarefa programada do Administrador.
    *   **SMBv1 & Signing Disabled:** Permite ataques de NTLM Relay.
    *   **Firewall & Defender:** Desactivados.

2.  **Kerberos:**
    *   **AS-REP Roasting:** Usuario `nopreauth.user` sen pre-autenticación.
    *   **Kerberoasting:** Usuario `svc_sql` con SPN asociado e servizo SQL real instalado.
    *   **Persistencia Avanzada**  
        *   **Silver Ticket (Persistencia por Servizo):**  
            *   **Conta obxectivo:** `svc_sql` (Hash NTLM: `ad2896ecfb9b443720bab09bb020f852`)  
            *   **SPN:** `MSSQLSvc/VULN-DC-01.vuln-he.lab:1433`  
            *   **Capacidades:**  
                - Forxado de TGS para MSSQL válido 10 anos  
                - Acceso persistente como Administrador ao servizo SQL  
                - Execución remota vía `xp_cmdshell`  
                - Escalada a SYSTEM mediante SeImpersonatePrivilege  
        *   **Golden Ticket (Persistencia Total de Dominio):**  
            *   **Conta crítica:** `krbtgt` (Hash NTLM)  
            *   **Capacidades:**  
                - Forxado de TGT válido para TODO o dominio durante 10 anos  
                - Acceso ilimitado a calquera recurso/servizo  
                - Non require comunicación co KDC  
                - Practicamente indetectable  

3.  **Password Spraying:**  
    *   Contrasinais débiles en `brais.t` e `maria.g` (presentes en rockyou.txt).

4.  **Privilexios e ACLs:**  
    *   **SeBackupPrivilege:** Usuario `brais.t` pode ler `NTDS.dit`.  
    *   **SeImpersonatePrivilege:** Usuario `maria.g` vulnerable a ataques tipo Potato.  

5.  **ACLs Débiles:**  
    *   **GenericAll ACL:** Grupo `HelpDesk` (usuario `helpdesk.user`) ten control total sobre `maria.g`.
        *    **Explotación viable:** Mediante `rpcclient` desde Linux (cambio remoto de contrasinal sen necesidade de shell).

## Despregamento

### 1. Requisitos Previos (Descargas)

Debido ás restricións de descarga automática, debes descargar manualmente o instalador de SQL Server e colocalo no directorio raíz do proxecto **antes** de executar Packer.

1.  **Windows Server 2019 ISO:** [Microsoft Evaluation Center](https://www.microsoft.com/es-es/evalcenter/download-windows-server-2019)  
2.  **SQL Server 2019 Express (Inglés - Offline Installer):**  
    Debes obter o ficheiro `SQLEXPR_x64_ENU.exe` (aprox. 250MB).  
    Para iso:  
    1. Usa un ordenador con Windows  
    2. Descarga o instalador web oficial (pequeno): [SQL2019-SSEI-Expr.exe](https://go.microsoft.com/fwlink/?linkid=866658).  
    3. Execútao  
    4.  Na xanela que se abre:  
        - Selecciona **"Download Media"** (Descargar medios).  
        - Selecciona paquete **Express Core**.  
        - Selecciona idioma **English**.  
        - Escolle o cartafol onde gardalo.  
    5. Cando remate, terás o ficheiro `SQLEXPR_x64_ENU.exe`. Móveo ao cartafol do teu proxecto Packer (vía USB, cartafol compartido, `scp`, etc.).

### 2. Construción da Imaxe

1.  Edita `windows2019.pkr.hcl` coa ruta e checksum da túa ISO de Windows Server 2019.
2.  Asegúrate de que `SQLEXPR_x64_ENU.exe` está no mesmo cartafol.
3.  Executa:
    ```bash
    packer init .
    packer build .
    ```

### 3. Importación e Configuración Final

1.  Importa a VM resultante (`VULN-DC-01.ovf`) en VirtualBox.
    ```bash
    $ tree output-autogenerated_1
    output-autogenerated_1
    ├── VULN-DC-01-disk001.vmdk
    └── VULN-DC-01.ovf
    ```

2.  **IMPORTANTE:** Antes de arrincar a máquina, comproba a configuración de rede en VirtualBox:
    *   **Adaptador 1:** 
        - Conectado: **"Host-Only Adapter" (Adaptador só anfitrión)**  
        - Nome: **vboxnet0**

3.  Arrinca a máquina. A IP estará configurada estaticamente en `192.168.56.100`

