// GPU_Checker.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "stdafx.h"
#include <iostream>
#include <fcntl.h>
#include <io.h>

using namespace std;

CString m_csGPUname;

bool HasNvidiaGPU()
{
    HRESULT hres;

    // Initialize COM
    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) {
        return false; // COM initialization failed
    }

    // Set COM security levels
    hres = CoInitializeSecurity(
        NULL,
        -1,                          // COM negotiates authentication
        NULL,                        // Authentication services
        NULL,                        // Reserved
        RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication 
        RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation
        NULL,                        // Authentication info
        EOAC_NONE,                   // Additional capabilities 
        NULL                         // Reserved
    );

    if (FAILED(hres)) 
    {
        CoUninitialize();
        return false; // Security initialization failed
    }

    // Obtain the initial locator to WMI
    IWbemLocator* pLoc = NULL;

    hres = CoCreateInstance(
        CLSID_WbemLocator,
        0,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (LPVOID*)&pLoc);

    if (FAILED(hres)) 
    {
        CoUninitialize();
        return false; // Failed to create IWbemLocator object
    }

    // Connect to the root\cimv2 namespace
    IWbemServices* pSvc = NULL;

    hres = pLoc->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"), // WMI namespace
        NULL,                    // User name
        NULL,                    // User password
        0,                       // Locale             
        NULL,                    // Security flags
        0,                       // Authority        
        0,                       // Context object     
        &pSvc                    // IWbemServices proxy
    );

    if (FAILED(hres)) {
        pLoc->Release();
        CoUninitialize();
        return false; // Could not connect to WMI namespace
    }

    // Set the proxy so that impersonation of the client occurs
    hres = CoSetProxyBlanket(
        pSvc,                        // Indicates the proxy to set
        RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx 
        RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx 
        NULL,                        // Server principal name 
        RPC_C_AUTHN_LEVEL_CALL,      // Authentication level
        RPC_C_IMP_LEVEL_IMPERSONATE, // Impersonation level
        NULL,                        // Authentication info
        EOAC_NONE                    // Additional capabilities 
    );

    if (FAILED(hres)) 
    {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return false; // Could not set proxy blanket
    }

    // Execute a WMI query to get GPU information
    IEnumWbemClassObject* pEnumerator = NULL;
    hres = pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t("SELECT Name, AdapterCompatibility FROM Win32_VideoController"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator);

    if (FAILED(hres)) 
    {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return false; // Query for GPU information failed
    }

    // Iterate over the query results
    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;
    bool foundNvidia = false;

    while (pEnumerator) 
    {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

        if (0 == uReturn) break; // No more results

        VARIANT vtName;
        VARIANT vtAdapterCompatibility;

        // Get the Name property
        hr = pclsObj->Get(L"Name", 0, &vtName, 0, 0);
        if (SUCCEEDED(hr) && vtName.vt == VT_BSTR && vtName.bstrVal != NULL) 
        {
            CString gpuName(vtName.bstrVal);
            if (gpuName.MakeLower().Find(L"nvidia") != -1)
            {
                foundNvidia = true;
                m_csGPUname = gpuName;
            }
        }
        VariantClear(&vtName);

        // Get the AdapterCompatibility property
        hr = pclsObj->Get(L"AdapterCompatibility", 0, &vtAdapterCompatibility, 0, 0);
        if (SUCCEEDED(hr))
        {
            CString adapterCompatibility(vtAdapterCompatibility.bstrVal);
            if (adapterCompatibility.MakeLower().Find(L"nvidia") != -1) {
                foundNvidia = true;
            }
        }
        VariantClear(&vtAdapterCompatibility);

        pclsObj->Release();

        if (foundNvidia) break; // NVIDIA GPU found, exit loop
    }

    // Cleanup
    pEnumerator->Release();
    pSvc->Release();
    pLoc->Release();
    CoUninitialize();

    return foundNvidia;
}

int main()
{
    _setmode(_fileno(stdout), _O_U16TEXT);

    if (HasNvidiaGPU() == true)
    {
        std::wcout << "Has NVIDIA GPU: "<< (LPCTSTR)m_csGPUname << std::endl;
    }
    
    system("Pause");
    return 0;
}

