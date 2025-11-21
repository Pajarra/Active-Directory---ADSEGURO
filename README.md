            -------------------------
           |ACTIVE DIRECTORY ADSEGURO|
            -------------------------
            
Projeto de Active Directory para a matéria de Metodologia de Projetos do curso superior de tecnologia em segurança cibernética pelo SENAI.

------------------------------------------------------------------------------------------------------------------------------------------------------

Pré-requisitos:
   - Windows Server 2022
   - Acesso de Administrador
   - Conexão de rede
   - Disco E:\ disponível

------------------------------------------------------------------------------------------------------------------------------------------------------

Execução
1. Executar como administrador
Set-ExecutionPolicy Bypass -Scope Process -Force

2. Rodar o script
.\ADSEGURO_Setup.ps1

3. O sistema será reiniciado durante a execução.

4. Após o PC ligar novamente, acesse pela conta de administrador do domínio e rode novamente o script repetindo os passos 1 e 2.

------------------------------------------------------------------------------------------------------------------------------------------------------

Pós-Instalação
Para verificar se tudo funcionou, execute os comandos:

Get-ADDomain
Get-SmbShare
Get-GPO -All | Where DisplayName -like "GPO_*"

------------------------------------------------------------------------------------------------------------------------------------------------------

Configuração Opcional

Edite as variáveis no início do script se necessário:

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

# Usuários exemplo ----------------------- Esta parte foi adicionada ao script apenas para atender às requisições solicitadas pela demanda. Em um ambiente real, deve ser removida.
$UserList = @(
    @{ User="ana.silva";     Dept="RH";  FullName="Ana Silva" },
    @{ User="carlos.santos"; Dept="FIN"; FullName="Carlos Santos" },
    @{ User="roberto.alves"; Dept="TI";  FullName="Roberto Alves" }
)


------------------------------------------------------------------------------------------------------------------------------------------------------

Configurações Manuais Necessárias

Após a instalação, configure manualmente pelo GPMC (aperte windows+R e digite gpmc.msc):

Redirecionamento de pastas nas GPOs: GPO_RH_Redirect, GPO_FIN_Redirect, GPO_TI_Redirect
