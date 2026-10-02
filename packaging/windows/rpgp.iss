; rPGP's Windows installer: a per-user Inno Setup script around the one
; self-contained rpgp.exe that every release already ships.
;
; The windows job of .github/workflows/release.yml compiles it with the Inno
; Setup it pins, 7.1.0, and the script uses directives that compiler has and
; 6.x does not, so an older one stops at the first rather than building
; something else. To compile it by hand, from the root of the repository:
;
;   ISCC.exe --define=AppVersion=0.1.4
;            --define=SourceExe=C:\full\path\to\rpgp-v0.1.4-x86_64.exe
;            --output-dir=C:\somewhere\outside\the\tree
;            packaging\windows\rpgp.iss
;
; (one line). Without --output-dir ISCC writes into packaging\windows\Output.
; AppVersion has to be the version the exe carries, X.Y.Z with nothing after
; it, since it also becomes the setup's numeric file version; the workflow
; reads it from the exe's ProductVersion. packaging/windows/README.md says how
; to check that a given setup exe wraps the released rpgp.exe byte for byte.
;
; ASCII only, so the question of which encoding ISCC reads it in never
; arises: it has taken UTF-8 without a byte-order mark since 6.3.0, and since
; 7.0.2 it refuses to compile a byte that is not valid in the encoding it
; settles on. Comments sit on lines of their own: a trailing ";" is part of a
; directive's value.

#ifndef AppVersion
  #error Pass --define=AppVersion=X.Y.Z, the version of the exe being wrapped
#endif
#ifndef SourceExe
  #error Pass --define=SourceExe= with the full path of rpgp-vX.Y.Z-x86_64.exe
#endif

[Setup]
; Never change this. Inno names the uninstall entry after it (jzbz.rPGP_is1
; under HKCU), which is how a newer installer finds the installed one and
; replaces it in place, and the winget manifest pins that name as the
; ProductCode. It is the winget identifier on purpose.
AppId=jzbz.rPGP
AppName=rPGP
AppVersion={#AppVersion}
AppPublisher=Jonathan Zeppettini
AppPublisherURL=https://jz.bz/
AppSupportURL=https://github.com/jzbz/rpgp/issues
AppUpdatesURL=https://github.com/jzbz/rpgp/releases
AppCopyright=Copyright (c) 2026 Jonathan Zeppettini
; The Apps & Features name, kept to the bare name rather than "rPGP 0.1.4":
; winget matches the entry against the manifest's PackageName and Publisher,
; and reads the version from DisplayVersion, which is AppVersion.
UninstallDisplayName=rPGP
UninstallDisplayIcon={app}\rpgp.exe
VersionInfoVersion={#AppVersion}

; Per user, and never elevated. Setup asks for no administrator rights, so it
; runs as the person who will use rPGP, and the "Launch rPGP" box at the end
; starts the app as them too: an elevated installer run by a standard user
; through an administrator's password would start it as the administrator,
; and the key store it created would be in the wrong profile. In this mode the
; {auto...} constants mean the current user's folders, the uninstall entry
; and the App Paths key below go under HKCU, and no admin is needed to remove
; it. PrivilegesRequiredOverridesAllowed is left unset, so Setup ignores
; /ALLUSERS rather than turning this into a per-machine install.
PrivilegesRequired=lowest
; %LOCALAPPDATA%\Programs\rPGP. Not %LOCALAPPDATA%\rpgp, which is the key
; store's directory and no installer's business.
DefaultDirName={autopf}\rPGP
DisableDirPage=yes
DisableProgramGroupPage=yes

; A 64-bit Setup, new in Inno Setup 7, for a 64-bit program. It also makes
; ArchitecturesAllowed and ArchitecturesInstallIn64BitMode default to
; x64compatible: x64 Windows, and Arm64 Windows 11 running the exe under
; emulation, which is where rpgp.exe itself runs.
SetupArchitecture=x64
; Windows 10, the oldest Windows Rust's x86_64-pc-windows-msvc target still
; supports and the oldest rpgp.exe's manifest declares. Inno's default would
; let Windows 7 install a program that cannot start there.
MinVersion=10.0

SetupIconFile=..\..\crates\rpgp-gui\desktop\app.rpgp.rpgp.ico
WizardStyle=modern dynamic
; The default, written out because the installer's bytes depend on it, and
; the release checks that two compiles of the same exe come out identical.
Compression=lzma2/max
; Overridden by --output-filename in the workflow, which names the setup
; after the tag or commit being built, as it names the bare exe.
OutputBaseFilename=rpgp-v{#AppVersion}-x86_64-setup

; An upgrade has to replace an rpgp.exe that may be running, so Setup asks
; Restart Manager to close it first. The request is made with the messages
; Windows sends every program at sign-out, and rPGP leaves the answer to
; Windows' default, which agrees: on Windows 11 a silent upgrade, the way
; winget runs one, closed a running rPGP and replaced it in under two
; seconds. A silent setup closes it without asking; an interactive one names
; it and asks first. It is not started again afterwards, since Setup restarts
; only programs registered for that, and rPGP is not. Whatever rPGP had not
; finished is lost as it would be at sign-out: text typed into a dialog, a key
; still being generated, a decrypt cut short, which leaves its <output>.part
; behind. The store replaces each file whole, so what is in it stays as it was.
;
; yes, the default, written out because force was tried and is the wrong
; choice. The two differ only where the request fails: for a copy that does
; not answer it, or one it cannot reach (in the test, one started from
; another non-interactive window station). force ends that copy, along with
; whatever was being done in it, and nobody is asked. With yes Setup gives up
; instead, with exit code 5, and changes nothing: the old version stays
; installed and that copy keeps running. winget's default return codes for an
; Inno installer map exit code 5 to cancelled by the user, so winget says the
; upgrade was cancelled, though nobody cancelled it; closing rPGP and running
; the upgrade again fixes it. An upgrade that fails until rPGP is closed is
; the better of the two.
CloseApplications=yes

[Files]
; ignoreversion: an upgrade, a reinstall and a winget downgrade all replace
; the exe whatever version it carries. notimestamp: the exe's time on the
; runner is the moment it was built or copied, and storing it would make two
; compiles of the same bytes differ.
Source: "{#SourceExe}"; DestDir: "{app}"; DestName: "rpgp.exe"; Flags: ignoreversion notimestamp

[Icons]
; The Start Menu entry, and the reason this installer exists. No desktop
; shortcut. The icon is the one embedded in the exe, and no AppUserModelID is
; set, because the app sets none at run time and the two have to agree for
; the taskbar to group a pinned shortcut with the running window.
Name: "{autoprograms}\rPGP"; Filename: "{app}\rpgp.exe"; WorkingDir: "{app}"; Comment: "Manage OpenPGP certificates and keys"

[Registry]
; The rpgp command, in place of the one winget's portable package put on
; PATH: an App Paths entry makes Win+R "rpgp" and `start rpgp` find the exe,
; from a normal, not elevated, Run box or prompt. Tried from elevated,
; non-interactive processes on a test machine, an HKCU App Paths name did not
; resolve, so nothing is promised there.
; It does not put rpgp on PATH for a shell, and nothing here changes PATH.
; Removed, key and all, on uninstall.
Root: HKA; Subkey: "Software\Microsoft\Windows\CurrentVersion\App Paths\rpgp.exe"; ValueType: string; ValueName: ""; ValueData: "{app}\rpgp.exe"; Flags: uninsdeletekey

[Run]
; Offered at the end of an interactive install only. skipifsilent covers
; /SILENT as well as /VERYSILENT, so winget, which passes one or the other,
; never starts the app.
Filename: "{app}\rpgp.exe"; WorkingDir: "{app}"; Description: "{cm:LaunchProgram,rPGP}"; Flags: nowait postinstall skipifsilent

; No [UninstallDelete] section, and there must never be one. The uninstaller
; removes what this script installed and then the folder if it is empty. The
; keys live in %LOCALAPPDATA%\rpgp (secret keys, revocations, trust lists)
; and %APPDATA%\pgp.cert.d (certificates), both written by the app and both
; outside {app}, and removing rPGP is not a request to delete them. The
; release workflow installs and uninstalls this on its runner and fails if a
; file placed in either beforehand is gone.
