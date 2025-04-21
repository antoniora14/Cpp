// Event_Handlers.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <Windows.h>
#include <iostream>

using namespace std;

HANDLE hEvent;

DWORD WINAPI Thread1(LPVOID lpParam)
{
    WaitForSingleObject(hEvent, INFINITE);
    cout << "Thread 1 Running" << endl;
    return 0;
}

DWORD WINAPI Thread2(LPVOID lpParam)
{
    cout << "Thread 2 Running" << endl;
    SetEvent(hEvent);
    return 0;
}


int main()
{
    cout << "\t\t ------- EVENT HANDLER EXAMPLE ------- " << endl;
    cout << endl;

    HANDLE hThread1, hThread2;
    DWORD  dwThread1ID, dwThread2ID;

    hEvent = CreateEvent(NULL, FALSE, FALSE, L"Event1");
    if (hEvent == NULL) cout << "CreateEvent function failed with error: " << GetLastError() << endl;

    hThread1 = CreateThread(NULL, 0, Thread1, NULL, 0, &dwThread1ID);
    if (hThread1 == NULL) cout << "CreateThread function failed with error: " << GetLastError() << endl;

    hThread2 = CreateThread(NULL, 0, Thread2, NULL, 0, &dwThread2ID);
    if (hThread2 == NULL) cout << "CreateThread function failed with error: " << GetLastError() << endl;

    // wait until object is on signaled state
    WaitForSingleObject(hThread1, INFINITE);
    WaitForSingleObject(hThread2, INFINITE);

    // close handles of threads and event
    CloseHandle(hThread1);
    CloseHandle(hThread2);
    CloseHandle(hEvent);

    system("PAUSE");
    return 0;
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
