; Inno Setup script. Build:  iscc /DAppVersion=0.1.0 /DSourceExe=<path to runet-direct.exe> runet-direct.iss
; Silent install for scripts and tests:  runet-direct-setup-x86_64.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART

#ifndef AppVersion
  #define AppVersion "0.1.0"
#endif
#ifndef SourceExe
  #define SourceExe "..\..\target\x86_64-pc-windows-msvc\release\runet-direct.exe"
#endif

[Setup]
AppId={{ADB1A9A6-DCBD-44FE-AD91-21A33EBD4A89}
AppName=runet-direct
AppVersion={#AppVersion}
AppVerName=runet-direct {#AppVersion}
AppPublisher=iResultMan
AppPublisherURL=https://github.com/iResultMan/runet-direct
AppSupportURL=https://github.com/iResultMan/runet-direct/issues
DefaultDirName={autopf}\runet-direct
DisableProgramGroupPage=yes
DisableDirPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=.
OutputBaseFilename=runet-direct-setup-x86_64
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
LicenseFile=..\..\LICENSE
UninstallDisplayName=runet-direct
ChangesEnvironment=yes
CloseApplications=no

[Languages]
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[CustomMessages]
russian.Registering=Регистрируем службу и загружаем список российских адресов (до минуты)...
english.Registering=Registering the service and downloading the list of Russian address blocks (up to a minute)...
russian.ShowStatus=Показать состояние службы
english.ShowStatus=Show the service status

[Files]
Source: "{#SourceExe}"; DestDir: "{app}"; Flags: ignoreversion

[Registry]
; Put the install folder on PATH so that "runet-direct" works in any terminal.
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"; ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; Check: NeedsAddPath('{app}')

[Run]
Filename: "{app}\runet-direct.exe"; Parameters: "install --in-place"; StatusMsg: "{cm:Registering}"; Flags: runhidden waituntilterminated
Filename: "{cmd}"; Parameters: "/k """"{app}\runet-direct.exe"" status"""; Description: "{cm:ShowStatus}"; Flags: postinstall nowait skipifsilent

[UninstallRun]
Filename: "{app}\runet-direct.exe"; Parameters: "uninstall --in-place"; Flags: runhidden waituntilterminated; RunOnceId: "RunetDirectUninstall"

[Code]
const
  EnvKey = 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment';

function NeedsAddPath(Param: string): Boolean;
var
  OrigPath: string;
begin
  if not RegQueryStringValue(HKEY_LOCAL_MACHINE, EnvKey, 'Path', OrigPath) then
  begin
    Result := True;
    exit;
  end;
  Result := Pos(';' + Uppercase(ExpandConstant('{app}')) + ';', ';' + Uppercase(OrigPath) + ';') = 0;
end;

{ An upgrade must be able to replace the executable, which the running service holds open. }
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
  Exe: string;
begin
  Exe := ExpandConstant('{app}\runet-direct.exe');
  if FileExists(Exe) then
    Exec(Exe, 'stop', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Result := '';
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Path, Entry: string;
  P: Integer;
begin
  if CurUninstallStep = usPostUninstall then
  begin
    if RegQueryStringValue(HKEY_LOCAL_MACHINE, EnvKey, 'Path', Path) then
    begin
      Entry := ';' + ExpandConstant('{app}');
      P := Pos(Uppercase(Entry), Uppercase(Path));
      if P > 0 then
      begin
        Delete(Path, P, Length(Entry));
        RegWriteExpandStringValue(HKEY_LOCAL_MACHINE, EnvKey, 'Path', Path);
      end;
    end;
  end;
end;
