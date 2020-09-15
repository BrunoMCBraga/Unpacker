from Util.MemoryDataInterpreter import MemoryDataInterpreter

class GetAtomNameW:

    DEFAULT_READ_SIZE = 50

    @staticmethod
    def get_arguments_list(vivisect_engine):
        arguments_array = vivisect_engine.get_function_arguments(3)

        n_atom = arguments_array[0]
        lp_buffer = arguments_array[1]
        n_size = arguments_array[2]

        atom_name = ''
        if lp_buffer != 0x0:
            bytes = vivisect_engine.read_memory(lp_buffer, n_size)
            atom_name = MemoryDataInterpreter.bytearray_to_unicode_string(bytes)

        return [hex(n_atom), atom_name]