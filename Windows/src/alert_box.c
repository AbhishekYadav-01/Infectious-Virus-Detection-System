#include <windows.h>
#include <stdio.h>
#include "../include/alert_box.h"

void show_alert(const char *message)
{
    MessageBoxA(NULL, message, "Virus Detected!", MB_ICONWARNING | MB_OK);
}
