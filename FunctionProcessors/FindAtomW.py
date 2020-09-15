from Util.MemoryDataInterpreter import MemoryDataInterpreter

class FindAtomW:

    DEFAULT_READ_SIZE = 50

    @staticmethod
    def get_arguments_list(vivisect_engine):
        arguments_array = vivisect_engine.get_function_arguments(1)

        lp_string = arguments_array[0]

        atom_name = ''
        if lp_string != 0x0:
            bytes = vivisect_engine.read_memory(lp_string, FindAtomW.DEFAULT_READ_SIZE)
            atom_name = MemoryDataInterpreter.bytearray_to_unicode_string(bytes)

        return [atom_name]