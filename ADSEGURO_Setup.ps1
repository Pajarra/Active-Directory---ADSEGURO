<#
    Setup-ADSEGURO_Completo.ps1
    Script COMPLETO com TODAS as GPOs específicas por departamento
    Baseado no documento "Active Directory - Estrutura.docx"
#>

# ============================
# CONFIGURAÇÕES INICIAIS
# ============================

$IPAddress = "192.168.1.10"
$Prefix = 24
$Gateway = "192.168.1.1"
$InterfaceAlias = "Ethernet"

$DomainName = "ADSEGURO.local"
$NetbiosName = "ADSEGURO"

# Caminhos
$SharesBase = "E:\Shares"
$RedirectBase = "E:\Redirect"

# Departamentos
$Departments = @("RH","FIN","TI","ADM")

# Grupos por departamento
$Groups = $Departments | ForEach-Object { "GRP_${_}_ACESSO" }

# Usuários exemplo
$UserList = @(
    @{ User="ana.silva";     Dept="RH";  FullName="Ana Silva" },
    @{ User="carlos.santos"; Dept="FIN"; FullName="Carlos Santos" },
    @{ User="roberto.alves"; Dept="TI";  FullName="Roberto Alves" }
)

# ============================
# FUNÇÕES PRINCIPAIS
# ============================

function Test-Administrator {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Ensure-StaticIP {
    Write-Host "Configurando IP estático..." -ForegroundColor Yellow
    try {
        $current = Get-NetIPAddress -InterfaceAlias $InterfaceAlias -AddressFamily IPv4 -ErrorAction SilentlyContinue
        if ($current.IPAddress -eq $IPAddress) {
            Write-Host "IP já configurado." -ForegroundColor Green
            return
        }
        Get-NetIPAddress -InterfaceAlias $InterfaceAlias -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false
        New-NetIPAddress -InterfaceAlias $InterfaceAlias -IPAddress $IPAddress -PrefixLength $Prefix -DefaultGateway $Gateway
        Set-DnsClientServerAddress -InterfaceAlias $InterfaceAlias -ServerAddresses @("127.0.0.1", "8.8.8.8")
        Write-Host "IP configurado: $IPAddress" -ForegroundColor Green
    }
    catch {
        Write-Error "Falha ao configurar IP: $($_.Exception.Message)"
        exit 1
    }
}

function Test-DomainController {
    try {
        Get-ADDomain -ErrorAction Stop | Out-Null
        return $true
    }
    catch {
        return $false
    }
}

function Ensure-DC {
    if (Test-DomainController) {
        Write-Host "Servidor já é DC." -ForegroundColor Green
        return
    }

    Write-Host "Promovendo a Controlador de Domínio..." -ForegroundColor Yellow
    try {
        Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
        $SafeModePassword = ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force
        Install-ADDSForest -DomainName $DomainName -DomainNetbiosName $NetbiosName -SafeModeAdministratorPassword $SafeModePassword -InstallDNS -Force
        Write-Host "DC promovido. Reinicie e execute novamente." -ForegroundColor Green
        exit
    }
    catch {
        Write-Error "Falha na promoção: $($_.Exception.Message)"
        exit 1
    }
}

function Create-OUs {
    Write-Host "Criando OUs..." -ForegroundColor Yellow
    $BaseDN = (Get-ADDomain).DistinguishedName

    $OuStructure = @(
        @{ Name = "Administrativo"; Path = $BaseDN },
        @{ Name = "Servidores"; Path = "OU=Administrativo,$BaseDN" },
        @{ Name = "Workstations"; Path = "OU=Administrativo,$BaseDN" },
        @{ Name = "Departamentos"; Path = $BaseDN },
        @{ Name = "RH"; Path = "OU=Departamentos,$BaseDN" },
        @{ Name = "FIN"; Path = "OU=Departamentos,$BaseDN" },
        @{ Name = "TI"; Path = "OU=Departamentos,$BaseDN" },
        @{ Name = "ADM"; Path = "OU=Departamentos,$BaseDN" },
        @{ Name = "Grupos_Seguranca"; Path = $BaseDN }
    )

    foreach ($ou in $OuStructure) {
        try {
            if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$($ou.Name)'" -ErrorAction SilentlyContinue)) {
                New-ADOrganizationalUnit -Name $ou.Name -Path $ou.Path -ProtectedFromAccidentalDeletion $false
                Write-Host "OU criada: $($ou.Name)" -ForegroundColor Green
            }
        }
        catch {
            Write-Warning "OU $($ou.Name) - $($_.Exception.Message)"
        }
    }
}

function Create-Groups {
    Write-Host "Criando grupos de segurança..." -ForegroundColor Yellow
    $Path = "OU=Grupos_Seguranca,$((Get-ADDomain).DistinguishedName)"

    foreach ($groupName in $Groups) {
        try {
            if (-not (Get-ADGroup -Filter "Name -eq '$groupName'" -ErrorAction SilentlyContinue)) {
                New-ADGroup -Name $groupName -GroupScope Global -GroupCategory Security -Path $Path
                Write-Host "Grupo criado: $groupName" -ForegroundColor Green
            }
        }
        catch {
            Write-Warning "Grupo $groupName - $($_.Exception.Message)"
        }
    }
}

function Create-Users {
    Write-Host "Criando usuários..." -ForegroundColor Yellow
    foreach ($userInfo in $UserList) {
        $SamAccountName = $userInfo.User
        $Department = $userInfo.Dept
        $FullName = $userInfo.FullName
        $OUPath = "OU=$Department,OU=Departamentos,$((Get-ADDomain).DistinguishedName)"
        $GroupName = "GRP_${Department}_ACESSO"

        try {
            if (-not (Get-ADUser -Filter "SamAccountName -eq '$SamAccountName'" -ErrorAction SilentlyContinue)) {
                $UserParams = @{
                    Name              = $FullName
                    SamAccountName    = $SamAccountName
                    UserPrincipalName = "$SamAccountName@$DomainName"
                    DisplayName       = $FullName
                    GivenName         = $FullName.Split(" ")[0]
                    Surname           = $FullName.Split(" ")[1]
                    AccountPassword   = (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force)
                    Enabled           = $true
                    Path              = $OUPath
                    ChangePasswordAtLogon = $true
                }
                New-ADUser @UserParams
                Write-Host "Usuário criado: $SamAccountName" -ForegroundColor Green
            }
            Add-ADGroupMember -Identity $GroupName -Members $SamAccountName -ErrorAction SilentlyContinue
            Write-Host "Usuário $SamAccountName adicionado ao grupo $GroupName" -ForegroundColor Green
        }
        catch {
            Write-Warning "Usuário $SamAccountName - $($_.Exception.Message)"
        }
    }
}

function Create-Shares-With-Permissions {
    Write-Host "Criando pastas e compartilhamentos..." -ForegroundColor Yellow
    try {
        New-Item -Path $SharesBase -ItemType Directory -Force | Out-Null
        New-Item -Path $RedirectBase -ItemType Directory -Force | Out-Null

        $domain = (Get-ADDomain).NetBIOSName
        $admGroup = "GRP_ADM_ACESSO"
        $admAccount = "$domain\$admGroup"

        foreach ($dept in $Departments) {
            $folderPath = Join-Path $SharesBase $dept
            if (-not (Test-Path $folderPath)) {
                New-Item $folderPath -ItemType Directory -Force | Out-Null
            }

            Write-Host "Configurando permissões para: $dept" -ForegroundColor Cyan

            # Remove herança e configura permissões
            icacls $folderPath /inheritance:r | Out-Null
            icacls $folderPath /grant "Administrators:(F)" | Out-Null

            $groupName = "GRP_${dept}_ACESSO"
            $account = "$domain\$groupName"
            icacls $folderPath /grant "${account}:(M)" | Out-Null

            # ADM tem Full Control em todas as pastas (exceto na própria)
            if ($dept -ne "ADM") {
                icacls $folderPath /grant "${admAccount}:(F)" | Out-Null
            }

            # Compartilhamento
            $existingShare = Get-SmbShare -Name $dept -ErrorAction SilentlyContinue
            if ($existingShare) {
                Remove-SmbShare -Name $dept -Force
            }

            if ($dept -eq "ADM") {
                New-SmbShare -Name $dept -Path $folderPath -FullAccess @("Administrators", $admAccount)
            } else {
                New-SmbShare -Name $dept -Path $folderPath -FullAccess "Administrators" -ChangeAccess @($account, $admAccount)
            }
            
            Write-Host "Share criado: \\$env:COMPUTERNAME\$dept" -ForegroundColor Green
        }
    }
    catch {
        Write-Error "Falha ao criar shares: $($_.Exception.Message)"
    }
}

function Create-All-GPOs-Complete {
    Write-Host "Criando TODAS as GPOs com configurações COMPLETAS..." -ForegroundColor Yellow

    # GPO do Domínio - Segurança Básica
    Write-Host "  Configurando GPO_Padrao_Seguranca..." -ForegroundColor Cyan
    try {
        if (-not (Get-GPO -Name "GPO_Padrao_Seguranca" -ErrorAction SilentlyContinue)) {
            $gpo = New-GPO -Name "GPO_Padrao_Seguranca"
            
            # Política de Senhas
            Set-GPRegistryValue -Name "GPO_Padrao_Seguranca" -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "PasswordComplexity" -Type DWord -Value 1
            Set-GPRegistryValue -Name "GPO_Padrao_Seguranca" -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "MinimumPasswordLength" -Type DWord -Value 12
            Set-GPRegistryValue -Name "GPO_Padrao_Seguranca" -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "MaximumPasswordAge" -Type DWord -Value 0
            Set-GPRegistryValue -Name "GPO_Padrao_Seguranca" -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "MinimumPasswordAge" -Type DWord -Value 1
            Set-GPRegistryValue -Name "GPO_Padrao_Seguranca" -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "LockoutBadCount" -Type DWord -Value 5
            Set-GPRegistryValue -Name "GPO_Padrao_Seguranca" -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "ResetLockoutCount" -Type DWord -Value 30
            Set-GPRegistryValue -Name "GPO_Padrao_Seguranca" -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "LockoutDuration" -Type DWord -Value 30
            
            # Firewall
            Set-GPRegistryValue -Name "GPO_Padrao_Seguranca" -Key "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" -ValueName "EnableFirewall" -Type DWord -Value 1
            
            # Windows Update automático
            Set-GPRegistryValue -Name "GPO_Padrao_Seguranca" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "NoAutoUpdate" -Type DWord -Value 0
            Set-GPRegistryValue -Name "GPO_Padrao_Seguranca" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "AUOptions" -Type DWord -Value 4
            
            Write-Host "    GPO_Padrao_Seguranca configurada com políticas de segurança" -ForegroundColor Green
        }
        New-GPLink -Name "GPO_Padrao_Seguranca" -Target (Get-ADDomain).DistinguishedName -LinkEnabled Yes
    }
    catch {
        Write-Warning "Erro GPO Domínio: $($_.Exception.Message)"
    }

    # GPO Workstations
    Write-Host "  Configurando GPO_Padronizacao_Workstations..." -ForegroundColor Cyan
    try {
        if (-not (Get-GPO -Name "GPO_Padronizacao_Workstations" -ErrorAction SilentlyContinue)) {
            $gpo = New-GPO -Name "GPO_Padronizacao_Workstations"
            
            # Bloqueio de tela após 10 min
            Set-GPRegistryValue -Name "GPO_Padronizacao_Workstations" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" -ValueName "ScreenSaveTimeOut" -Type String -Value "600"
            Set-GPRegistryValue -Name "GPO_Padronizacao_Workstations" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" -ValueName "ScreenSaverIsSecure" -Type String -Value "1"
            
            Write-Host "    GPO_Padronizacao_Workstations configurada" -ForegroundColor Green
        }
        New-GPLink -Name "GPO_Padronizacao_Workstations" -Target "OU=Workstations,OU=Administrativo,$((Get-ADDomain).DistinguishedName)" -LinkEnabled Yes
    }
    catch {
        Write-Warning "Erro GPO Workstations: $($_.Exception.Message)"
    }

    # GPO Servidores
    Write-Host "  Configurando GPO_Padronizacao_Servidores..." -ForegroundColor Cyan
    try {
        if (-not (Get-GPO -Name "GPO_Padronizacao_Servidores" -ErrorAction SilentlyContinue)) {
            $gpo = New-GPO -Name "GPO_Padronizacao_Servidores"
            
            # Logs detalhados
            Set-GPRegistryValue -Name "GPO_Padronizacao_Servidores" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" -ValueName "MaxSize" -Type DWord -Value 67108864
            Set-GPRegistryValue -Name "GPO_Padronizacao_Servidores" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" -ValueName "MaxSize" -Type DWord -Value 67108864
            
            Write-Host "    GPO_Padronizacao_Servidores configurada" -ForegroundColor Green
        }
        New-GPLink -Name "GPO_Padronizacao_Servidores" -Target "OU=Servidores,OU=Administrativo,$((Get-ADDomain).DistinguishedName)" -LinkEnabled Yes
    }
    catch {
        Write-Warning "Erro GPO Servidores: $($_.Exception.Message)"
    }

    # GPO RH Restrictions
    Write-Host "  Configurando GPO_RH_Restrictions..." -ForegroundColor Cyan
    try {
        if (-not (Get-GPO -Name "GPO_RH_Restrictions" -ErrorAction SilentlyContinue)) {
            $gpo = New-GPO -Name "GPO_RH_Restrictions"
            
            # Bloqueia CMD
            Set-GPRegistryValue -Name "GPO_RH_Restrictions" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" -ValueName "DisableCMD" -Type DWord -Value 2
            
            # Bloqueia Painel de Controle
            Set-GPRegistryValue -Name "GPO_RH_Restrictions" -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ValueName "NoControlPanel" -Type DWord -Value 1
            
            Write-Host "    GPO_RH_Restrictions configurada com bloqueios" -ForegroundColor Green
        }
        New-GPLink -Name "GPO_RH_Restrictions" -Target "OU=RH,OU=Departamentos,$((Get-ADDomain).DistinguishedName)" -LinkEnabled Yes
    }
    catch {
        Write-Warning "Erro GPO RH: $($_.Exception.Message)"
    }

    # GPO FIN Restrictions
    Write-Host "  Configurando GPO_FIN_Restrictions..." -ForegroundColor Cyan
    try {
        if (-not (Get-GPO -Name "GPO_FIN_Restrictions" -ErrorAction SilentlyContinue)) {
            $gpo = New-GPO -Name "GPO_FIN_Restrictions"
            
            # Mesmas restrições do RH
            Set-GPRegistryValue -Name "GPO_FIN_Restrictions" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" -ValueName "DisableCMD" -Type DWord -Value 2
            Set-GPRegistryValue -Name "GPO_FIN_Restrictions" -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ValueName "NoControlPanel" -Type DWord -Value 1
            
            Write-Host "    GPO_FIN_Restrictions configurada com bloqueios" -ForegroundColor Green
        }
        New-GPLink -Name "GPO_FIN_Restrictions" -Target "OU=FIN,OU=Departamentos,$((Get-ADDomain).DistinguishedName)" -LinkEnabled Yes
    }
    catch {
        Write-Warning "Erro GPO FIN: $($_.Exception.Message)"
    }

    # GPO TI Scripts
    Write-Host "  Configurando GPO_TI_Scripts..." -ForegroundColor Cyan
    try {
        if (-not (Get-GPO -Name "GPO_TI_Scripts" -ErrorAction SilentlyContinue)) {
            $gpo = New-GPO -Name "GPO_TI_Scripts"
            
            # Permite CMD e PowerShell
            Set-GPRegistryValue -Name "GPO_TI_Scripts" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" -ValueName "DisableCMD" -Type DWord -Value 0
            
            Write-Host "    GPO_TI_Scripts configurada (CMD liberado)" -ForegroundColor Green
        }
        New-GPLink -Name "GPO_TI_Scripts" -Target "OU=TI,OU=Departamentos,$((Get-ADDomain).DistinguishedName)" -LinkEnabled Yes
    }
    catch {
        Write-Warning "Erro GPO TI: $($_.Exception.Message)"
    }

    # GPO ADMINS - CONFIGURADA!
    Write-Host "  Configurando GPO_Admins..." -ForegroundColor Cyan
    try {
        if (-not (Get-GPO -Name "GPO_Admins" -ErrorAction SilentlyContinue)) {
            $gpo = New-GPO -Name "GPO_Admins"
            
            # Acesso Remoto habilitado para admins
            Set-GPRegistryValue -Name "GPO_Admins" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ValueName "fDenyTSConnections" -Type DWord -Value 0
            
            # Logon remoto permitido sem autenticação de nível de rede
            Set-GPRegistryValue -Name "GPO_Admins" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ValueName "UserAuthentication" -Type DWord -Value 0
            
            # Auditoria detalhada para ações administrativas
            Set-GPRegistryValue -Name "GPO_Admins" -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -ValueName "ProcessCreationIncludeCmdLine_Enabled" -Type DWord -Value 1
            
            # PowerShell Execution Policy - Unrestricted para admins
            Set-GPRegistryValue -Name "GPO_Admins" -Key "HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" -ValueName "ExecutionPolicy" -Type String -Value "Unrestricted"
            
            Write-Host "    GPO_Admins configurada com privilégios administrativos" -ForegroundColor Green
        }
        New-GPLink -Name "GPO_Admins" -Target "OU=ADM,OU=Departamentos,$((Get-ADDomain).DistinguishedName)" -LinkEnabled Yes
    }
    catch {
        Write-Warning "Erro GPO Admins: $($_.Exception.Message)"
    }

    # GPOs de Redirect (criadas mas configuradas manualmente depois)
    $redirectGPOs = @(
        @{ Name = "GPO_RH_Redirect"; Target = "OU=RH,OU=Departamentos,$((Get-ADDomain).DistinguishedName)" },
        @{ Name = "GPO_FIN_Redirect"; Target = "OU=FIN,OU=Departamentos,$((Get-ADDomain).DistinguishedName)" },
        @{ Name = "GPO_TI_Redirect"; Target = "OU=TI,OU=Departamentos,$((Get-ADDomain).DistinguishedName)" }
    )

    foreach ($gpo in $redirectGPOs) {
        try {
            if (-not (Get-GPO -Name $gpo.Name -ErrorAction SilentlyContinue)) {
                New-GPO -Name $gpo.Name | Out-Null
                Write-Host "    $($gpo.Name) criada" -ForegroundColor Green
            }
            New-GPLink -Name $gpo.Name -Target $gpo.Target -LinkEnabled Yes -ErrorAction SilentlyContinue | Out-Null
        }
        catch {
            Write-Warning "Erro $($gpo.Name): $($_.Exception.Message)"
        }
    }

    Write-Host "Todas as GPOs foram criadas e configuradas!" -ForegroundColor Green
    Write-Host "NOTA: GPOs de Redirect precisam de configuração manual de Folder Redirection via GPMC" -ForegroundColor Yellow
}

function Create-LogonScript {
    Write-Host "Criando script de logon para mapeamento de unidades..." -ForegroundColor Yellow
    
    $netlogonPath = "\\$env:COMPUTERNAME\NETLOGON"
    $scriptPath = Join-Path $netlogonPath "MapDrives.vbs"
    
    $scriptContent = @"
' Script de mapeamento de unidades por departamento
Set WshNetwork = CreateObject("WScript.Network")
Set objUser = CreateObject("ADSystemInfo")
Set objCurrentUser = GetObject("LDAP://" & objUser.UserName)

' Obtém o departamento do usuário
department = ""
On Error Resume Next
For Each group In objCurrentUser.MemberOf
    If InStr(1, group, "GRP_", 1) > 0 Then
        If InStr(1, group, "RH_ACESSO") > 0 Then department = "RH"
        If InStr(1, group, "FIN_ACESSO") > 0 Then department = "FIN" 
        If InStr(1, group, "TI_ACESSO") > 0 Then department = "TI"
        If InStr(1, group, "ADM_ACESSO") > 0 Then department = "ADM"
    End If
Next
On Error GoTo 0

' Mapeia unidade S: conforme departamento
If department <> "" Then
    WshNetwork.MapNetworkDrive "S:", "\\$env:COMPUTERNAME\" & department
End If
"@

    try {
        if (-not (Test-Path $netlogonPath)) {
            New-Item -Path $netlogonPath -ItemType Directory -Force | Out-Null
        }
        
        $scriptContent | Out-File -FilePath $scriptPath -Encoding ASCII
        Write-Host "Script de logon criado: $scriptPath" -ForegroundColor Green
    }
    catch {
        Write-Warning "Erro ao criar script de logon: $($_.Exception.Message)"
    }
}

function Set-DNSForwarder {
    Write-Host "Configurando DNS forwarder..." -ForegroundColor Yellow
    try {
        Add-DnsServerForwarder -IPAddress "8.8.8.8" -ErrorAction SilentlyContinue
        Write-Host "DNS forwarder configurado." -ForegroundColor Green
    }
    catch {
        Write-Warning "Não foi possível configurar DNS forwarder: $($_.Exception.Message)"
    }
}

# ============================
# EXECUÇÃO PRINCIPAL
# ============================

Write-Host "`n=== CONFIGURAÇÃO COMPLETA DO ADSEGURO ===`n" -ForegroundColor Cyan

if (-not (Test-Administrator)) {
    Write-Error "Execute como Administrador!"
    exit 1
}

try {
    Ensure-StaticIP
    Ensure-DC
    Set-DNSForwarder
    Create-OUs
    Create-Groups
    Create-Users
    Create-Shares-With-Permissions
    Create-All-GPOs-Complete
    Create-LogonScript

    Write-Host "`n=== AMBIENTE ADSEGURO CONFIGURADO COM SUCESSO ===" -ForegroundColor Green
    Write-Host "Domain: $DomainName" -ForegroundColor White
    Write-Host "IP: $IPAddress" -ForegroundColor White
    Write-Host "Shares: $($Departments -join ', ')" -ForegroundColor White
    Write-Host "Usuários: $($UserList.User -join ', ')" -ForegroundColor White
    Write-Host "GPOs criadas e configuradas:" -ForegroundColor White
    Write-Host "  • Domínio: GPO_Padrao_Seguranca" -ForegroundColor White
    Write-Host "  • Workstations: GPO_Padronizacao_Workstations" -ForegroundColor White
    Write-Host "  • Servidores: GPO_Padronizacao_Servidores" -ForegroundColor White
    Write-Host "  • RH: GPO_RH_Redirect, GPO_RH_Restrictions" -ForegroundColor White
    Write-Host "  • FIN: GPO_FIN_Redirect, GPO_FIN_Restrictions" -ForegroundColor White
    Write-Host "  • TI: GPO_TI_Redirect, GPO_TI_Scripts" -ForegroundColor White
    Write-Host "  • ADM: GPO_Admins (CONFIGURADA)" -ForegroundColor Green
    Write-Host "`nScript de logon criado para mapeamento automático de unidades" -ForegroundColor White
}
catch {
    Write-Error "Erro durante execução: $($_.Exception.Message)"
    exit 1
}