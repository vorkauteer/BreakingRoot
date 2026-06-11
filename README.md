1. Core (ядро CLI)

`main.cpp` – запуск цикла ввода команд, отрисовка приглашения.
`app.cpp` – реализация всех Command* функций: CommandRecon, CommandBypassAmsiEtw, CommandLsass, CommandPowerShellEncoded, CommandCreateScheduledTask, CommandSetRegistryAutoRun, CommandSignedProxyCertutil.
`command.cpp` – парсинг ввода, преобразование текста в команду (CommandType), вызов соответствующих обработчиков.
`common.h` – определения Target (оставлен для совместимости), CliState (контекст), перечисления доменов и модулей.

2. Defense – обнаружение механизмов защиты

`FullDefenseRecon(DefenseStatus* ds)` – заполняет структуру статусами:
`CheckPPL` – RunAsPPL в реестре LSA.
`CheckCredentialGuard` – наличие процесса lsaiso.exe.
`CheckHVCI` – DeviceGuard / HypervisorEnforcedCodeIntegrity.
`CheckSecureBoot` – статус UEFI Secure Boot.
`CheckTestSigning` – режим тестовой подписи драйверов.
`DetectEDR` – поиск известных процессов EDR (CrowdStrike, CarbonBlack, Defender, Tanium и др.).
`PrintDefenseStatus` – вывод результатов.

3. Recon – разведка системы

`RunHostInfo()` – имя компьютера и текущий пользователь.
`RunOsInfo()` – версия и сборка Windows, архитектура процессора.
`RunUserEnum()` – локальные пользователи (NetUserEnum).
`RunGroupEnum()` – локальные группы.
`RunShareEnum()` – сетевые ресурсы (шары).
`RunServiceEnum()` – перечисление служб Windows (только работающие).
`RunSessionEnum()` – активные сессии (процессы с интерактивными пользователями).

4. Evasion – обход защиты
  
`BypassAmsiViaPatch()` – патч amsi.dll: AmsiScanBuffer на xor eax,eax; ret.
`DisableEtw()` – отключение ETW через NtSetInformationProcess.
`SysOpenProcess(DWORD pid, DWORD access)` – прямой syscall NtOpenProcess без обхода хуков ntdll.

5. Creds – извлечение учётных данных
  
`GetLsassPid()` – поиск PID lsass.exe.
`RemovePPLViaKernel()` – загрузка mimidrv.sys (или использование уже загруженного) и отправка IOCTL 0x88002003 для снятия PPL.
`DumpLsassViaMiniDumpSyscall(pid, outPath)` – открытие LSASS через SysOpenProcess и дамп через MiniDumpWriteDump (обходит многие callback'и, но не обходит PPL без драйвера).
`CommandLsass()` – основная команда: проверка защиты, при необходимости снятие PPL, затем дамп.

6. Persistence – закрепление и драйверы
  
`LoadDriverViaService(driverPath, serviceName)` – создание и запуск драйвера как службы ядра.
`UnloadDriverService(serviceName)` – остановка и удаление службы ядра.
`ExploitDellDBUtil_2_3() / ExploitMSIRTCore64()` – заглушки для эксплуатации уязвимых драйверов (CVE-2021-21551, CVE-2019-16098).
`CommandCreateScheduledTask()` – создание скрытой задачи планировщика (запуск при загрузке от SYSTEM).
`CommandSetRegistryAutoRun()` – запись в автозагрузку HKCU.
`CommandSignedProxyCertutil()` – загрузка файла через легальный certutil.exe.

|Команда|Описание|
|---|---|
|`help`|Показать справку|
|`exit`|Выйти|
|`status`|Показать текущий контекст и состояние|
|`list`|Список доступных доменов (core, recon, creds, session, config)|
|`use <домен>`|Войти в домен (например, `use recon`)|
|`use <домен/модуль>`|Выбрать модуль (например, `use recon/hostinfo`)|
|`back`|Выйти из текущего домена/модуля|
|`show`|Показать текущий контекст|
|`run`|Запустить выбранный модуль (работает для `session/reset`, `session/show`, `config/verbose`)|
|`recon-all`|Быстрая разведка защиты (PPL, HVCI, CG, EDR, …)|
|`bypass`|Отключить AMSI и ETW|
|`lsass`|Продвинутый дамп LSASS (с обходом PPL через драйвер)|
|`ps-encode <command>`|Выполнить закодированную PowerShell-команду скрыто|
|`schtask-create <name> <exe>`|Создать скрытую задачу при загрузке (SYSTEM)|
|`reg-autorun <name> <data>`|Добавить запись в автозагрузку текущего пользователя|
|`proxy-certutil <url> <file>`|Скачать файл через `certutil` (обход ограничений)|

 Домены и модули (интерактивная навигация)

- **`use recon`** – войти в домен разведки.
    - `hostinfo`, `osinfo`, `userenum`, `groupenum`, `shareenum`, `serviceenum`, `sessionenum`
- **`use creds`** – войти в домен учётных данных.
    - `lsass`, `sam`, `lsa`, `dpapi`, `ntlm`, `kerberos` (реализован только `lsass`)
- **`use session`** – домен управления сессией.
    - `reset` – сброс состояния фреймворка.
    - `show` – вывод `status`.
- **`use config`** – домен настроек.
    - `verbose` – включение/выключение подробного режима.

Сборка
```sh
cmake -S . -B build -G "Ninja"
cmake --build build --config Release
```

