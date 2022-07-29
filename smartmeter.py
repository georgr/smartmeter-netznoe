from binascii import unhexlify
from datetime import datetime
from Cryptodome.Cipher import AES


class NetzNOESmartmeterMessage(object):

    # converts apdu hex to int
    @classmethod
    def bytes_to_int(cls, bytes):
        result = 0
        for b in bytes:
            result = result * 256 + b
        return result

    # decrpyts a smartmeter message with the key from netz noe
    @classmethod
    def decrypt(cls, key, data):
        system_title = data[22:38]
        frame_counter = data[44:52]
        frame = unhexlify(data[52:560])
        encryption_key = unhexlify(key)
        init_vector = unhexlify(system_title + frame_counter)
        cipher = AES.new(encryption_key, AES.MODE_GCM, nonce=init_vector)
        decrypted_data = cipher.decrypt(frame).hex()

        result_hex_values = {
            'year': decrypted_data[12:16],
            'month': decrypted_data[16:18],
            'day': decrypted_data[18:20],
            'hour': decrypted_data[22:24],
            'minute': decrypted_data[24:26],
            'second': decrypted_data[26:28],
            'a_plus': decrypted_data[86:94],
            'a_minus': decrypted_data[124:132],
            'p_plus': decrypted_data[162:170],
            'p_minus': decrypted_data[200:208],
            'voltage_l1': decrypted_data[238:242],
            'voltage_l2': decrypted_data[272:276],
            'voltage_l3': decrypted_data[306:310],
            'current_l1': decrypted_data[340:344],
            'current_l2': decrypted_data[374:378],
            'current_l3': decrypted_data[408:412],
            'power_factor': decrypted_data[442:446],
            'meter_number': decrypted_data[462:486]
        }

        # print(result_hex_values)

        decrypted_dict = {
            'timestamp': datetime(
                cls.bytes_to_int(unhexlify(result_hex_values['year'])),
                cls.bytes_to_int(unhexlify(result_hex_values['month'])),
                cls.bytes_to_int(unhexlify(result_hex_values['day'])),
                cls.bytes_to_int(unhexlify(result_hex_values['hour'])),
                cls.bytes_to_int(unhexlify(result_hex_values['minute'])),
                cls.bytes_to_int(unhexlify(result_hex_values['second']))
            ),
            'a_plus': cls.bytes_to_int(unhexlify(result_hex_values['a_plus'])),
            'a_minus': cls.bytes_to_int(unhexlify(result_hex_values['a_minus'])),
            'p_plus': cls.bytes_to_int(unhexlify(result_hex_values['p_plus'])),
            'p_minus': cls.bytes_to_int(unhexlify(result_hex_values['p_minus'])),
            'voltage_l1': cls.bytes_to_int(unhexlify(result_hex_values['voltage_l1'])),
            'voltage_l2': cls.bytes_to_int(unhexlify(result_hex_values['voltage_l2'])),
            'voltage_l3': cls.bytes_to_int(unhexlify(result_hex_values['voltage_l3'])),
            'current_l1': cls.bytes_to_int(unhexlify(result_hex_values['current_l1'])),
            'current_l2': cls.bytes_to_int(unhexlify(result_hex_values['current_l2'])),
            'current_l3': cls.bytes_to_int(unhexlify(result_hex_values['current_l3'])),
            'power_factor': cls.bytes_to_int(unhexlify(result_hex_values['power_factor'])),
            'meter_number': cls.bytes_to_int(unhexlify(result_hex_values['meter_number']))
        }

        return decrypted_dict


if __name__ == '__main__':

    # sample key and data from evn netz noe
    # https://www.netz-noe.at/Download-(1)/Smart-Meter/218_9_SmartMeter_Kundenschnittstelle_lektoriert_14.aspx

    sample_key = '36C66639E48A8CA4D6BC8B282A793BBB'
    sample_data = '68FAFA6853FF000167DB084B464D675000000981F8200000002388D5AB4F97515AAFC6B88D2F85DAA7A0E3C0C40D004535C397C9D037AB7DBDA329107615444894A1A0DD7E85F02D496CECD3FF46AF5FB3C9229CFE8F3EE4606AB2E1F409F36AAD2E50900A4396FC6C2E083F373233A69616950758BFC7D63A9E9B6E99E21B2CBC2B934772CA51FD4D69830711CAB1F8CFF25F0A329337CBA51904F0CAED88D61968743C8454BA922EB00038182C22FE316D16F2A9F544D6F75D51A4E92A1C4EF8AB19A2B7FEAA32D0726C0ED80229AE6C0F7621A4209251ACE2B2BC66FF0327A653BB686C756BE033C7A281F1D2A7E1FA31C3983E15F8FD16CC5787E6F517166814146853FF110167419A3CFDA44BE438C96F0E38BF83D98316'


    print(NetzNOESmartmeterMessage().decrypt(sample_key, sample_data))


