# smartmeter-netznoe

Simple static class to decrypt apdu messages and decode data from EVN Netz NÖ smart meters.
To get the key to decrypt messages from your smart meter follow the [official guide](https://www.netz-noe.at/Download-(1)/Smart-Meter/218_9_SmartMeter_Kundenschnittstelle_lektoriert_14.aspx).

## required libraries

AES decryption ```pip3 install pycryptodomex```

## usage

```python
 # sample key and data from evn netz noe
 # https://www.netz-noe.at/Download-(1)/Smart-Meter/218_9_SmartMeter_Kundenschnittstelle_lektoriert_14.aspx
    
 sample_key = '36C66639E48A8CA4D6BC8B282A793BBB'
 sample_data = '68FAFA6853FF000167DB084B464D675000000981F8200000002388D5AB4F97515AAFC6B88D2F85DAA7A0E3C0C40D004535C397C9D037AB7DBDA329107615444894A1A0DD7E85F02D496CECD3FF46AF5FB3C9229CFE8F3EE4606AB2E1F409F36AAD2E50900A4396FC6C2E083F373233A69616950758BFC7D63A9E9B6E99E21B2CBC2B934772CA51FD4D69830711CAB1F8CFF25F0A329337CBA51904F0CAED88D61968743C8454BA922EB00038182C22FE316D16F2A9F544D6F75D51A4E92A1C4EF8AB19A2B7FEAA32D0726C0ED80229AE6C0F7621A4209251ACE2B2BC66FF0327A653BB686C756BE033C7A281F1D2A7E1FA31C3983E15F8FD16CC5787E6F517166814146853FF110167419A3CFDA44BE438C96F0E38BF83D98316'

 print(NetzNOESmartmeterMessage().decrypt(sample_key, sample_data))

```

## sample output

```python
{
    'timestamp': datetime.datetime(2021, 9, 27, 9, 47, 15), 
    'a_plus': 12937, 
    'a_minus': 0, 
    'p_plus': 0, 
    'p_minus': 0, 
    'voltage_l1': 2337, 
    'voltage_l2': 0, 
    'voltage_l3': 0, 
    'current_l1': 0, 
    'current_l2': 0, 
    'current_l3': 0, 
    'power_factor': 1000, 
    'meter_number': 67013263506611294340757425949
}

```
