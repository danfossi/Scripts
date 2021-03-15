<#
    .SYNOPSIS
    Fetches the price of various cryptocurrencies.
 
    .DESCRIPTION
    Fetches the price of various cryptocurrencies via cryptocompare's API.
 
    .PARAMETER Coin
    Specifies the coin abbreviation.
 
    .PARAMETER Refresh
    Specifies the refresh time (in seconds).
 
    .PARAMETER Currency
    Specifies the preferred currency for output.
 
    .INPUTS
    None. You cannot pipe objects.
 
    .OUTPUTS
    Returns a string with the price of the coin.
 
    .EXAMPLE 1: Refresh Ethereum Price every 10 minutes (EUR)
    PS> ./Get-CryptoPrice.ps1 -coin ETH -currency EUR -refresh 600    
    
    .EXAMPLE 2: Refresh Ethereum Price every 10 minutes (USD)
    PS> ./Get-CryptoPrice.ps1 -coin ETH -currency USD -refresh 600    
#>
 
# Parameters
param(
    [Parameter(Mandatory=$false)][string]$coin,
    [Parameter(Mandatory=$false)][ValidateSet("EUR", "USD")][string]$currency,
    [Parameter(Mandatory=$false)][string]$refresh
)
 
# Autofill if blank
if (!$coin) {
    $coin = "BTC"
}
if (!$currency) {
    $currency = "EUR"
}   
if (!$refresh) {
    $refresh = "600"
}   
 
# Var
if ($currency -eq "EUR"){
    $currency_symbol = [char]8364
}
elseif ($currency -eq "USD"){
    $currency_symbol = "$"
}
else {
    $currency_symbol = [char]8364
}
 
clear
 
Write-Host "=======================================" -ForegroundColor Yellow
Write-Host "          " $coin.ToUpper() "Price Ticker"  -ForegroundColor Yellow
Write-Host "======================================="  -ForegroundColor Yellow
 
# Window Title
$Host.UI.RawUI.WindowTitle = $coin.ToUpper() + " Price Ticker"
 
# Window Size
$pshost = get-host
$pswindow = $pshost.ui.rawui
$newsize = $pswindow.windowsize
$newsize.width = 40
$newsize.height = 18
$pswindow.windowsize = $newsize
 
# Buffer size
$pshost = get-host
$pswindow = $pshost.ui.rawui
$newsize = $pswindow.buffersize
$newsize.width = 40
$newsize.height = 3000
$pswindow.buffersize = $newsize
 
#Loop
while($true){
    #Query URL
    $query_url = "https://min-api.cryptocompare.com/data/price?fsym="+$coin+"&"+"tsyms="+$currency
 
    #Time
    $Date = Get-Date
 
    try {
        $last = Invoke-RestMethod -Uri $query_url -ErrorAction SilentlyContinue
    }
    catch {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $last = Invoke-RestMethod -Uri $query_url -ErrorAction Stop
    }
    
    start-sleep $refresh
    
    try {
        $current = Invoke-RestMethod -Uri $query_url -ErrorAction SilentlyContinue
    }
    catch {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $current = Invoke-RestMethod -Uri $query_url -ErrorAction Stop
    }
    
    # Write output
    if ($current.$currency -gt $last.$currency){
        #Trend Up
        Write-Host "+" $Date "-" $current.$currency $currency_symbol -ForegroundColor Green
    }
    elseif ($current.$currency -lt $last.$currency){
        #Trend Down
        Write-Host "-" $Date "-" $current.$currency $currency_symbol -ForegroundColor Red
    }
    elseif ($current.$currency -eq $last.$currency){
        #Stable Trend
        Write-Host "=" $Date "-" $current.$currency $currency_symbol
    }
    else {
        #?!?
        Write-Host "?" $Date "-" $current.$currency $currency_symbol -ForegroundColor Magenta
    }
}
