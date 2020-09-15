

class MemoryDataInterpreter:

    @staticmethod
    def bytearray_to_ascii_string(bytes):

        string_bytes = bytearray()

        for i in range(0, len(bytes)):
            if bytes[i] == 0x00:
                break
            string_bytes.insert(i, bytes[i])

        decoded_string = None
        try:
            decoded_string = string_bytes.decode('ascii')
        except UnicodeDecodeError:
            print("Util->MemodyDataInterpreter->bytearray_to_ascii_string: failed to decode string using ascii decoder.")
            return bytes

        return decoded_string

    #Removing 0x00 from unicode string...simplicity...
    @staticmethod
    def bytearray_to_unicode_string(bytes):

        string_bytes = bytearray()

        is_even = True if len(bytes)%2 == 0 else False

        for i in range(0, len(bytes), 2):
            byte1 = bytes[i]

            byte2 = 0x0
            if not is_even:
                if i+1 >= len(bytes):
                    break
            byte2 = bytes[i + 1]

            if byte1 == 0x0 and byte2 == 0x0:
                break
            string_bytes.insert(i, byte1)
            #string_bytes.insert(i + 1, byte2)

        decoded_string = None
        try:
            decoded_string = string_bytes.decode('utf-8')
            return decoded_string
        except UnicodeDecodeError:
            print("Util->MemodyDataInterpreter: failed to decode string using utf-8 decoder.")

        try:
            decoded_string = string_bytes.decode('utf-16')
        except UnicodeDecodeError:
            print("Util->MemodyDataInterpreter->bytearray_to_unicode_string: failed to decode string using utf-16 decoder.")
            return bytes

        #print([hex(arg) for arg in string_bytes])
        return decoded_string

    @staticmethod
    def extract_bytes(bytes, size):

        extracted_bytes = bytearray()

        for i in range(0, size):
            extracted_bytes.insert(i, bytes[i])

        return extracted_bytes

