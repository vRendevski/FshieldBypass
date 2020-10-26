#include "pch.h"
#include <mono/jit/jit.h>

//Some typedef's and declarations
typedef void(__cdecl* t_mono_thread_attach)(MonoDomain*);
t_mono_thread_attach fnThreadAttach;

typedef  MonoDomain* (__cdecl* t_mono_get_root_domain)(void);
t_mono_get_root_domain fnGetRootDomain;

typedef MonoAssembly* (__cdecl* t_mono_assembly_open)(const char*, MonoImageOpenStatus*);
t_mono_assembly_open fnAssemblyOpen;

typedef MonoImage* (__cdecl* t_mono_assembly_get_image)(MonoAssembly*);
t_mono_assembly_get_image fnAssemblyGetImage;

typedef MonoClass* (__cdecl* t_mono_class_from_name)(MonoImage*, const char*, const char*);
t_mono_class_from_name fnClassFromName;

typedef MonoMethod* (__cdecl* t_mono_class_get_method_from_name)(MonoClass*, const char*, int);
t_mono_class_get_method_from_name fnMethodFromName;

typedef MonoObject* (__cdecl* t_mono_runtime_invoke)(MonoMethod*, void*, void**, MonoObject**);
t_mono_runtime_invoke fnRuntimeInvoke;

typedef const char* (__cdecl* t_mono_assembly_getrootdir)(void);
t_mono_assembly_getrootdir fnGetRootDir;

//Function for injecting the specified mono assembly
void InjectMonoAssembly() 
{
    HMODULE mono = LoadLibraryW(L"mono.dll");

    fnThreadAttach = (t_mono_thread_attach)GetProcAddress(mono, "mono_thread_attach");
    fnGetRootDomain = (t_mono_get_root_domain)GetProcAddress(mono, "mono_get_root_domain");
    fnAssemblyOpen = (t_mono_assembly_open)GetProcAddress(mono, "mono_assembly_open");
    fnAssemblyGetImage = (t_mono_assembly_get_image)GetProcAddress(mono, "mono_assembly_get_image");
    fnClassFromName = (t_mono_class_from_name)GetProcAddress(mono, "mono_class_from_name");
    fnMethodFromName = (t_mono_class_get_method_from_name)GetProcAddress(mono, "mono_class_get_method_from_name");
    fnRuntimeInvoke = (t_mono_runtime_invoke)GetProcAddress(mono, "mono_runtime_invoke");
    fnGetRootDir = (t_mono_assembly_getrootdir)GetProcAddress(mono, "mono_assembly_getrootdir");

    MonoDomain* domain      =   fnGetRootDomain();
                                fnThreadAttach(domain);
    MonoAssembly* assembly  =   fnAssemblyOpen("C:\\DizzyClient.dll", NULL);
    MonoImage* image        =   fnAssemblyGetImage(assembly);
    MonoClass* klass        =   fnClassFromName(image, "DizzyHacks", "Ready");
    MonoMethod* method      =   fnMethodFromName(klass, "Init", 0);
                                fnRuntimeInvoke(method, NULL, NULL, NULL);
}

void UnhookMono(void* toHook)
{
    DWORD flProtect;
    VirtualProtect(toHook, 6u, PAGE_EXECUTE_READWRITE, &flProtect);

    DWORD originalJump = *(DWORD*)((DWORD)toHook + 1);

    //Hook - Removes FShields hook (restores rusts original bytes)
    *(BYTE*)toHook = 0x55;
    *(BYTE*)((DWORD)toHook + 1) = 0x8B;
    *(BYTE*)((DWORD)toHook + 2) = 0xEC;
    *(BYTE*)((DWORD)toHook + 3) = 0x51;
    *(BYTE*)((DWORD)toHook + 4) = 0x57;
    *(BYTE*)((DWORD)toHook + 5) = 0x8B;
    *(BYTE*)((DWORD)toHook + 6) = 0x7D;
    *(BYTE*)((DWORD)toHook + 7) = 0x08;

    //Inject Mono - Injects our cheat
    InjectMonoAssembly();

    //Restore original - Bypasses fshield's integrity check - Restores FShields hook
    *(BYTE*)toHook = 0xE9;
    *(DWORD*)((DWORD)toHook + 1) = originalJump;
    *(BYTE*)((DWORD)toHook + 5) = 0xC3;

    DWORD temp;
    VirtualProtect(toHook, 6u, flProtect, &temp);
}

bool HackThread(HMODULE hModule)
{
    void* exportFunction = GetProcAddress(GetModuleHandleA("mono.dll"), "mono_assembly_load_from_full");
    UnhookMono(exportFunction);

    return 1;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        CreateThread(0, 0, (LPTHREAD_START_ROUTINE)HackThread, hModule, 0, 0);
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

