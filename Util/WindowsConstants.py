from FunctionProcessors.GetProcAddress import GetProcAddress
from FunctionProcessors.GetModuleHandle import GetModuleHandle
from FunctionProcessors.GetModuleHandleA import GetModuleHandleA
from FunctionProcessors.GetModuleHandleW import GetModuleHandleW
from FunctionProcessors.RegOpenKeyExW import RegOpenKeyExW
from FunctionProcessors.WriteProcessMemory import WriteProcessMemory
from FunctionProcessors.VirtualAlloc import VirtualAlloc
from FunctionProcessors.memmove import memmove
from FunctionProcessors.memset import memset
from FunctionProcessors.HeapAlloc import HeapAlloc
from FunctionProcessors.HeapFree import HeapFree
from FunctionProcessors.RtlAllocateHeap import RtlAllocateHeap
from FunctionProcessors.RtlFreeHeap import RtlFreeHeap
from FunctionProcessors.GlobalAlloc import GlobalAlloc
from FunctionProcessors.GlobalFree import GlobalFree
from FunctionProcessors.LocalAlloc import LocalAlloc
from FunctionProcessors.LocalFree import LocalFree
from FunctionProcessors.malloc import malloc
from FunctionProcessors.free import free
from FunctionProcessors.lstrcatA import lstrcatA
from FunctionProcessors.WideCharToMultiByte import WideCharToMultiByte
from FunctionProcessors.MultiByteToWideChar import MultiByteToWideChar
from FunctionProcessors.GetStringTypeA import GetStringTypeA
from FunctionProcessors.GetStringTypeW import GetStringTypeW
from FunctionProcessors.CreateThread import CreateThread
from FunctionProcessors.CreateProcessA import CreateProcessA
from FunctionProcessors.CreateProcessW import CreateProcessW
from FunctionProcessors.CreateMutexA import CreateMutexA
from FunctionProcessors.OpenMutex import OpenMutex
from FunctionProcessors.atexit import atexit
from FunctionProcessors.FindAtomA import FindAtomA
from FunctionProcessors.FindAtomW import FindAtomW
from FunctionProcessors.AddAtomA import AddAtomA
from FunctionProcessors.AddAtomW import AddAtomW
from FunctionProcessors.GetAtomNameA import GetAtomNameA
from FunctionProcessors.GetAtomNameW import GetAtomNameW
from FunctionProcessors.SetUnhandledExceptionFilter import SetUnhandledExceptionFilter
from FunctionProcessors.RtlUserThreadStart import RtlUserThreadStart


class WindowsConstants:
    FUNCTION_ARGUMENT_PROCESSORS = {'GetProcAddress': GetProcAddress.get_arguments_list,
                                    'GetModuleHandle': GetModuleHandle.get_arguments_list,
                                    'GetModuleHandleA': GetModuleHandleA.get_arguments_list,
                                    'GetModuleHandleW': GetModuleHandleW.get_arguments_list,
                                    'RegOpenKeyExW': RegOpenKeyExW.get_arguments_list,
                                    'WriteProcessMemory': WriteProcessMemory.get_arguments_list,
                                    'VirtualAlloc': VirtualAlloc.get_arguments_list,
                                    'memmove': memmove.get_arguments_list,
                                    'memset': memset.get_arguments_list,
                                    'HeapAlloc': HeapAlloc.get_arguments_list,
                                    'HeapFree': HeapFree.get_arguments_list,
                                    'GlobalAlloc': GlobalAlloc.get_arguments_list,
                                    'GlobalFree': GlobalFree.get_arguments_list,
                                    'RtlAllocateHeap': RtlAllocateHeap.get_arguments_list,
                                    'RtlFreeHeap': RtlFreeHeap.get_arguments_list,
                                    'LocalAlloc': LocalAlloc.get_arguments_list,
                                    'LocalFree': LocalFree.get_arguments_list,
                                    'malloc': malloc.get_arguments_list,
                                    'free': free.get_arguments_list,
                                    'lstrcatA': lstrcatA.get_arguments_list,
                                    'WideCharToMultiByte': WideCharToMultiByte.get_arguments_list,
                                    'MultiByteToWideChar': MultiByteToWideChar.get_arguments_list,
                                    'GetStringTypeA': GetStringTypeA.get_arguments_list,
                                    'GetStringTypeW': GetStringTypeW.get_arguments_list,
                                    'CreateThread': CreateThread.get_arguments_list,
                                    'CreateProcessA': CreateProcessA.get_arguments_list,
                                    'CreateProcessW': CreateProcessW.get_arguments_list,
                                    'CreateMutexA': CreateMutexA.get_arguments_list,
                                    'OpenMutex': OpenMutex.get_arguments_list,
                                    'atexit': atexit.get_arguments_list,
                                    'FindAtomA': FindAtomA.get_arguments_list,
                                    'FindAtomW': FindAtomW.get_arguments_list,
                                    'AddAtomA': AddAtomA.get_arguments_list,
                                    'AddAtomW': AddAtomW.get_arguments_list,
                                    'GetAtomNameA': GetAtomNameA.get_arguments_list,
                                    'GetAtomNameW': GetAtomNameW.get_arguments_list,
                                    'SetUnhandledExceptionFilter': SetUnhandledExceptionFilter.get_arguments_list,
                                    'RtlUserThreadStart': RtlUserThreadStart.get_arguments_list
                                    }

    FUNCTION_RESULT_PROCESSORS = {'VirtualAlloc': VirtualAlloc.process_result,
                                  'HeapAlloc': HeapAlloc.process_result,
                                  'RtlAllocateHeap': RtlAllocateHeap.process_result,
                                  'GlobalAlloc': GlobalAlloc.process_result,
                                  'LocalAlloc': LocalAlloc.process_result,
                                  'malloc': malloc.process_result}