# Imprime os enderecos pelos quais o Vulnetic pode ser acessado.
# Chamado pelo status.bat. Separado do .bat porque inline com pipes escapados
# quebra no cmd do Windows.
$ips = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
       Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } |
       ForEach-Object {
         $ip = $_.IPAddress
         $alias = $_.InterfaceAlias
         # ordem importa: virtual/overlay primeiro, senao 172.x casa como "local"
         if ($ip -like '100.*') { $tag = 'Tailscale - funciona de fora da rede' }
         elseif ($alias -match 'WSL|Default Switch|Hyper-V|VirtualBox|VMware|Loopback|vEthernet') { $tag = 'interface virtual - NAO usar' }
         elseif ($ip -like '192.168.*' -or $ip -like '10.*' -or $ip -match '^172\.(1[6-9]|2[0-9]|3[01])\.') { $tag = 'rede local - mesmo Wi-Fi/Ethernet' }
         else { $tag = 'nao classificado' }
         [PSCustomObject]@{ IP = $ip; Alias = $alias; Tag = $tag }
       } |
       Sort-Object { if ($_.Tag -like '*virtual*') { 3 } elseif ($_.Tag -like '*local*') { 1 } elseif ($_.Tag -like 'Tailscale*') { 2 } else { 4 } }

foreach ($e in $ips) {
  Write-Host ("  http://{0}:8787  {1}" -f $e.IP, $e.Tag)
}
