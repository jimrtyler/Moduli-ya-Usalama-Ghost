# 👻 Moduli ya Usalama wa Ghost
**Zana ya Kuimarisha Usalama wa Windows na Azure Inayotegemea PowerShell**

> **Uimarishaji wa makusudi wa usalama kwa mipaka ya Windows na mazingira ya Azure.** Ghost inatoa kazi za uimarishaji zinazotegemea PowerShell ambazo zinaweza kusaidia kupunguza mitandao ya mashambulizi ya kawaida kwa kuzima huduma na itifaki zisizohitajika.

## ⚠️ Maonyo Muhimu

**JARIBIO LINAHITAJIKA**: Daima jaribu Ghost kwanza katika mazingira yasiyo ya uzalishaji. Kuzima huduma kunaweza kuathiri kazi halali za biashara.

**HAKUNA DHAMANA**: Ingawa Ghost inalenga mitandao ya mashambulizi ya kawaida, hakuna zana ya usalama inayoweza kuzuia mashambulizi yote. Hii ni sehemu moja katika mkakati wa kina wa usalama.

**ATHARI ZA UENDESHAJI**: Baadhi ya kazi zinaweza kuathiri utendaji wa mfumo. Kagua kila mpangilio kwa uangalifu kabla ya utekelezaji.

**TATHMINI YA KITAALAMU**: Kwa mazingira ya uzalishaji, shauriana na wataalamu wa usalama ili kuhakikisha kuwa mipangilio inafanana na mahitaji ya shirika lako.

## 📊 Mazingira ya Usalama

Uharibifu wa ransomware uliongezeka hadi **dola bilioni 57 mwaka 2025**, utafiti unaonyesha kuwa mashambulizi mengi yaliyofanikiwa yanatumia huduma za msingi za Windows na usanidi mbaya. Mitandao ya mashambulizi ya kawaida ni pamoja na:

- **Asilimia 90 ya matukio ya ransomware** yamehusisha unyonyaji wa RDP
- **Udhaifu wa SMBv1** umewezesha mashambulizi kama WannaCry na NotPetya
- **Macros za nyaraka** zinaendelea kuwa njia kuu ya kutuma malware
- **Mashambulizi yanayotegemea USB** yanaendelea kulenga mitandao ya air-gap
- **Matumizi mabaya ya PowerShell** yameongezeka kwa kiasi kikubwa katika miaka ya hivi karibuni

## 🛡️ Kazi za Usalama za Ghost

Ghost inatoa **kazi 16 za uimarishaji wa Windows** pamoja na **muunganiko wa usalama wa Azure**:

### Uimarishaji wa Windows Endpoint

| Kazi | Kusudi | Maelezo |
|----------|---------|----------------|
| `Set-RDP` | Inasimamia ufikiaji wa Remote Desktop | Inaweza kuathiri usimamizi wa mbali |
| `Set-SMBv1` | Inadhibiti itifaki ya urithi ya SMB | Inahitajika kwa mifumo ya zamani sana |
| `Set-AutoRun` | Inadhibiti AutoPlay/AutoRun | Inaweza kuathiri rahisi ya mtumiaji |
| `Set-USBStorage` | Inapunguza vifaa vya uhifadhi wa USB | Inaweza kuathiri matumizi halali ya USB |
| `Set-Macros` | Inadhibiti utekelezaji wa macros za Office | Inaweza kuathiri nyaraka zilizo na macros |
| `Set-PSRemoting` | Inasimamia PowerShell ya mbali | Inaweza kuathiri usimamizi wa mbali |
| `Set-WinRM` | Inadhibiti Windows Remote Management | Inaweza kuathiri usimamizi wa mbali |
| `Set-LLMNR` | Inasimamia itifaki ya utatuzi wa majina | Kwa kawaida ni salama kuzima |
| `Set-NetBIOS` | Inadhibiti NetBIOS juu ya TCP/IP | Inaweza kuathiri programu za urithi |
| `Set-AdminShares` | Inasimamia ugawiaji wa kiutawala | Inaweza kuathiri ufikiaji wa faili za mbali |
| `Set-Telemetry` | Inadhibiti ukusanyaji wa data | Inaweza kuathiri uwezo wa uchunguzi |
| `Set-GuestAccount` | Inasimamia akaunti ya mgeni | Kwa kawaida ni salama kuzima |
| `Set-ICMP` | Inadhibiti majibu ya ping | Inaweza kuathiri uchunguzi wa mtandao |
| `Set-RemoteAssistance` | Inasimamia Remote Assistance | Inaweza kuathiri uendeshaji wa help desk |
| `Set-NetworkDiscovery` | Inadhibiti ugunduzi wa mtandao | Inaweza kuathiri kuvinjari mtandao |
| `Set-Firewall` | Inasimamia Windows Firewall | Muhimu kwa usalama wa mtandao |

### Usalama wa Wingu la Azure

| Kazi | Kusudi | Mahitaji |
|----------|---------|--------------|
| `Set-AzureSecurityDefaults` | Inawezesha usalama wa msingi wa Azure AD | Ruhusa za Microsoft Graph |
| `Set-AzureConditionalAccess` | Inasanidi sera za ufikiaji | Leseni za Azure AD P1/P2 |
| `Set-AzurePrivilegedUsers` | Inakagua akaunti za kipekee | Ruhusa za Global Admin |

### Chaguzi za Uwekaji wa Kampuni

| Njia | Kesi ya Matumizi | Mahitaji |
|--------|----------|--------------|
| **Utekelezaji wa Moja kwa Moja** | Jaribio, mazingira madogo | Haki za msimamizi wa ndani |
| **Group Policy** | Mazingira ya kikoa | Msimamizi wa kikoa, usimamizi wa GP |
| **Microsoft Intune** | Vifaa vinavyosimamiwa na wingu | Leseni za Intune, Graph API |

## 🚀 Kuanza Haraka

### Tathmini ya Usalama
```powershell
# Pakia moduli ya Ghost
IEX(Invoke-WebRequest 'https://raw.githubusercontent.com/jimrtyler/Ghost/main/Ghost.ps1')

# Angalia hali ya usalama ya sasa
Get-Ghost
```

### Uimarishaji wa Msingi (Jaribu Kwanza)
```powershell
# Uimarishaji muhimu - jaribu kwanza katika mazingira ya maabara
Set-Ghost -SMBv1 -AutoRun -Macros

# Kagua mabadiliko
Get-Ghost
```

### Uwekaji wa Kampuni
```powershell
# Uwekaji wa Group Policy (mazingira ya kikoa)
Set-Ghost -SMBv1 -AutoRun -GroupPolicy

# Uwekaji wa Intune (vifaa vinavyosimamiwa na wingu)
Set-Ghost -SMBv1 -RDP -USBStorage -Intune
```

## 📋 Njia za Usakinishaji

### Chaguo la 1: Upakuaji wa Moja kwa Moja (Jaribio)
```powershell
IEX(Invoke-WebRequest 'https://raw.githubusercontent.com/jimrtyler/Ghost/main/Ghost.ps1')
```

### Chaguo la 2: Usakinishaji wa Moduli
```powershell
# Sakinisha kutoka PowerShell Gallery (wakati inapatikana)
Install-Module Ghost -Scope CurrentUser
Import-Module Ghost
```

### Chaguo la 3: Uwekaji wa Kampuni
```powershell
# Nakili kwenye eneo la mtandao kwa uwekaji wa Group Policy
# Sanidi hati za PowerShell za Intune kwa uwekaji wa wingu
```

## 💼 Mifano ya Kesi za Matumizi

### Biashara Ndogo
```powershell
# Ulinzi wa msingi na athari ndogo
Set-Ghost -SMBv1 -AutoRun -Macros -ICMP
```

### Mazingira ya Afya
```powershell
# Uimarishaji unaolenga HIPAA
Set-Ghost -SMBv1 -RDP -USBStorage -AdminShares -Telemetry
```

### Huduma za Kifedha
```powershell
# Usanidi wa usalama wa juu
Set-Ghost -RDP -SMBv1 -AutoRun -USBStorage -Macros -PSRemoting -AdminShares
```

### Shirika la Cloud-First
```powershell
# Uwekaji unaosimamiwa na Intune
Connect-IntuneGhost -Interactive
Set-Ghost -SMBv1 -RDP -AutoRun -Macros -Intune
```

## 🔍 Maelezo ya Kazi

### Kazi Kuu za Uimarishaji

#### Huduma za Mtandao
- **RDP**: Inazuia ufikiaji wa desktop ya mbali au kubadilisha bandari
- **SMBv1**: Inazima itifaki ya urithi ya kushiriki faili
- **ICMP**: Inazuia majibu ya ping kwa uchunguzi
- **LLMNR/NetBIOS**: Inazuia itifaki za urithi za utatuzi wa majina

#### Usalama wa Programu
- **Macros**: Inazima utekelezaji wa macros katika programu za Office
- **AutoRun**: Inazuia utekelezaji wa kiotomatiki kutoka vyombo vya kuondoa

#### Usimamizi wa Mbali
- **PSRemoting**: Inazima vipindi vya PowerShell vya mbali
- **WinRM**: Inasimamisha Windows Remote Management
- **Remote Assistance**: Inazuia miunganiko ya msaada wa mbali

#### Udhibiti wa Ufikiaji
- **Admin Shares**: Inazima ugawiaji wa C$, ADMIN$
- **Guest Account**: Inazima ufikiaji wa akaunti ya mgeni
- **USB Storage**: Inapunguza matumizi ya vifaa vya USB

### Muunganiko wa Azure
```powershell
# Unganisha na mpangaji wa Azure
Connect-AzureGhost -Interactive

# Wezesha mchaguo wa kawaida wa usalama
Set-AzureSecurityDefaults -Enable

# Sanidi ufikiaji wa masharti
Set-AzureConditionalAccess -BlockLegacyAuth -RequireMFA

# Kagua watumiaji wa kipekee
Set-AzurePrivilegedUsers -AuditOnly
```

### Muunganiko wa Intune (Mpya katika v2)
```powershell
# Unganisha na Intune
Connect-IntuneGhost -Interactive

# Weka kupitia sera za Intune
Set-IntuneGhost -Settings @{
    RDP = $true
    SMBv1 = $true
    USBStorage = $true
    Macros = $true
}
```

## ⚠️ Maelezo Muhimu

### Mahitaji ya Jaribio
- **Mazingira ya Maabara**: Jaribu kwanza mipangilio yote katika mazingira yaliyotengwa
- **Uwekaji wa Hatua kwa Hatua**: Weka polepole ili kutambua matatizo
- **Mpango wa Kurudi**: Hakikisha unaweza kurejesha mabadiliko ikiwa itahitajika
- **Nyaraka**: Rekodi mipangilio gani inafanya kazi kwa mazingira yako

### Athari Zinazowezekana
- **Uzalishaji wa Mtumiaji**: Baadhi ya mipangilio inaweza kuathiri michakato ya kila siku
- **Programu za Urithi**: Mifumo ya zamani inaweza kuhitaji itifaki maalum
- **Ufikiaji wa Mbali**: Fikiria athari kwa usimamizi halali wa mbali
- **Michakato ya Biashara**: Thibitisha kwamba mipangilio haivunji kazi muhimu

### Mipaka ya Usalama
- **Ulinzi wa Kina**: Ghost ni tabaka moja la usalama, si suluhisho kamilifu
- **Usimamizi wa Kuendelea**: Usalama unahitaji ufuatiliaji na marekebisho endelevu
- **Mafunzo ya Mtumiaji**: Udhibiti wa kiufundi lazima uongezane na uelewa wa usalama
- **Mageuzi ya Vitisho**: Njia mpya za mashambulizi zinaweza kupita ulinzi wa sasa

## 🎯 Mifano ya Mazingira ya Mashambulizi

Ingawa Ghost inalenga mitandao ya mashambulizi ya kawaida, uzuiaji maalum unategemea utekelezaji na jaribio sahihi:

### Mashambulizi ya Mtindo wa WannaCry
- **Upunguzaji**: `Set-Ghost -SMBv1` inazima itifaki dhaifu
- **Maelezo**: Hakikisha hakuna mfumo wa urithi unaohitaji SMBv1

### Ransomware Inayotegemea RDP
- **Upunguzaji**: `Set-Ghost -RDP` inazuia ufikiaji wa desktop ya mbali
- **Maelezo**: Inaweza kuhitaji njia mbadala za ufikiaji wa mbali

### Malware Inayotegemea Nyaraka
- **Upunguzaji**: `Set-Ghost -Macros` inazima utekelezaji wa macros
- **Maelezo**: Inaweza kuathiri nyaraka halali zilizo na macros

### Vitisho Vinavyopelekwa na USB
- **Upunguzaji**: `Set-Ghost -USBStorage -AutoRun` inapunguza utendaji wa USB
- **Maelezo**: Inaweza kuathiri matumizi halali ya vifaa vya USB

## 🏢 Vipengele vya Kampuni

### Msaada wa Group Policy
```powershell
# Tekeleza mipangilio kupitia rejista ya Group Policy
Set-Ghost -SMBv1 -RDP -AutoRun -GroupPolicy

# Mipangilio inatekelezwa katika kikoa chote baada ya GP kusasishwa
gpupdate /force
```

### Muunganiko wa Microsoft Intune
```powershell
# Unda sera za Intune kwa mipangilio ya Ghost
Set-IntuneGhost -Settings $GhostSettings -Interactive

# Sera zinawekwa kiotomatiki kwenye vifaa vinavyosimamiwa
```

### Ripoti za Utii
```powershell
# Zalisha ripoti ya tathmini ya usalama
Get-Ghost | Export-Csv -Path "SecurityAudit-$(Get-Date -Format 'yyyy-MM-dd').csv"

# Ripoti ya hali ya usalama ya Azure
Get-AzureGhost | Out-File "AzureSecurityReport.txt"
```

## 📚 Mazoea Bora

### Kabla ya Uwekaji
1. **Andika Hali ya Sasa**: Endesha `Get-Ghost` kabla ya mabadiliko
2. **Jaribu kwa Uangalifu**: Thibitisha katika mazingira yasiyo ya uzalishaji
3. **Panga Kurudi**: Jua jinsi ya kurejesha kila mpangilio
4. **Ukaguzi wa Wadau**: Hakikisha vitengo vya biashara vinakubali mabadiliko

### Wakati wa Uwekaji
1. **Mbinu ya Hatua kwa Hatua**: Weka kwanza kwa makundi ya jaribio
2. **Fuatilia Athari**: Angalia malalamiko ya watumiaji au matatizo ya mfumo
3. **Andika Matatizo**: Rekodi matatizo yoyote kwa marejeleo ya baadaye
4. **Wasiliana Mabadiliko**: Arifa watumiaji kuhusu maboresho ya usalama

### Baada ya Uwekaji
1. **Tathmini ya Kawaida**: Endesha `Get-Ghost` mara kwa mara ili kuthibitisha mipangilio
2. **Sasisha Nyaraka**: Weka usanidi wa sasa wa usalama
3. **Kagua Ufanisi**: Fuatilia matukio ya usalama
4. **Maboresho ya Kuendelea**: Rekebisha mipangilio kulingana na mazingira ya vitisho

## 🔧 Utatuzi wa Matatizo

### Matatizo ya Kawaida
- **Makosa ya Ruhusa**: Hakikisha kipindi cha PowerShell kilichopandishwa
- **Utegemezi wa Huduma**: Baadhi ya huduma zinaweza kuwa na utegemezi
- **Utangamano wa Programu**: Jaribu na programu za biashara
- **Muunganiko wa Mtandao**: Thibitisha kwamba ufikiaji wa mbali bado unafanya kazi

### Chaguzi za Urejeshaji
```powershell
# Wezesha tena huduma maalum ikiwa itahitajika
Set-RDP -Enable
Set-SMBv1 -Enable
Set-AutoRun -Enable
Set-Macros -Enable
```

## 👨‍💻 Kuhusu Mwandishi

**Jim Tyler** - Microsoft MVP kwa PowerShell
- **YouTube**: [@PowerShellEngineer](https://youtube.com/@PowerShellEngineer) (wafuasi 10,000+)
- **Jarida**: [PowerShell.News](https://powershell.news) - Ujasusi wa usalama wa kila wiki
- **Mwandishi**: "PowerShell for Systems Engineers"
- **Uzoefu**: Miongo ya kiotomatiki cha PowerShell na usalama wa Windows

## 📄 Leseni na Ukanusho

### Leseni ya MIT
Ghost inatolewa chini ya Leseni ya MIT kwa matumizi, marekebisho na usambazaji wa bure.

### Ukanusho wa Usalama
- **Hakuna Dhamana**: Ghost inatolewa "kama ilivyo" bila dhamana ya aina yoyote
- **Jaribio Linahitajika**: Daima jaribu kwanza katika mazingira yasiyo ya uzalishaji
- **Mwongozo wa Kitaalamu**: Shauriana na wataalamu wa usalama kwa uwekaji wa uzalishaji
- **Athari za Uendeshaji**: Waandishi hawajawajibika kwa usumbufu wowote wa uendeshaji
- **Usalama wa Kina**: Ghost ni sehemu moja katika mkakati kamili wa usalama

### Msaada
- **GitHub Issues**: [Ripoti makosa au omba vipengele](https://github.com/jimrtyler/Ghost/issues)
- **Nyaraka**: Tumia `Get-Help <function> -Full` kwa msaada wa kina
- **Jumuiya**: Majukwaa ya jumuiya ya PowerShell na usalama

---

**🔒 Imarisha hali yako ya usalama na Ghost - lakini daima jaribu kwanza.**

```powershell
# Anza na tathmini, si makadirio
Get-Ghost
```

**⭐ Toa nyota kwa hifadhi hii ikiwa Ghost inasaidia kuboresha hali yako ya usalama!**